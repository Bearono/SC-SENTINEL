"""
SENTINEL Docker 沙箱生命周期控制器
────────────────────────────────────────────────────────────────────────────
执行手册第 2.3 节 + 阶段三任务清单：

  1. 拉起 Docker 容器（sentinel-sandbox 镜像）
     - 特权模式（eBPF uprobe 需要 CAP_SYS_ADMIN）
     - 资源限制（CPU + 内存上限）
     - 数据卷挂载（将用户源码映射到容器内）
  2. 在容器内依次执行：
     a. 编译源码（AFL++ 插桩模式 afl-clang / afl-gcc）
     b. 后台启动 eBPF 监控脚本（bpftrace monitor.bt）
     c. 启动 AFL++ 模糊测试（afl-fuzz）
  3. 等待 AFL++ 运行完毕（或超时）
  4. 提取日志：
     - AFL++ findings/crashes/ 目录下的崩溃文件
     - eBPF JSON 行日志（/sentinel-work/logs/ebpf.log）
  5. 无论成功/超时/异常，finally 块强制 stop + remove 容器

重要：
  - 所有 docker-py 调用都是同步阻塞的！
  - 本模块中的函数应在 asyncio.to_thread() 中调用，防止阻塞事件循环。

依赖安装：
  pip install docker
"""
import json
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# ── eBPF 事件类型字符串 → EbpfEventType 枚举映射 ──────────────────────────────
_EBPF_EVENT_MAP = {
    "double_free":     "double_free",
    "use_after_free":  "use_after_free",
    "heap_overflow":   "heap_overflow",
    "null_deref":      "null_deref",
    "stack_overflow":  "stack_overflow",
    "out_of_bounds":   "out_of_bounds",
}


@dataclass
class SandboxResult:
    """沙箱验证结果，供 fuzzing_task 写入数据库"""

    # 是否触发了崩溃
    crash_found: bool = False

    # AFL++ 崩溃原始日志（终端输出）
    afl_crash_log: str = ""

    # 解析后的 eBPF 事件列表
    # 每项: {"ts": int, "event": str, "addr": str, "fn": str}
    ebpf_events: list[dict] = field(default_factory=list)

    # 总运行时间（秒）
    elapsed_seconds: float = 0.0

    # 容器是否因超时被强杀
    timed_out: bool = False

    # 错误信息（异常时填充）
    error: Optional[str] = None

    # AFL++ 执行数据（崩溃数量、执行次数等）
    afl_stats: dict = field(default_factory=dict)


def _get_docker_client():
    """获取 docker-py 客户端，连接宿主机 Docker 引擎"""
    import docker
    return docker.from_env()


def _build_compile_script(source_root: str, vuln_file: Optional[str] = None) -> str:
    """
    生成在容器内执行的编译脚本（AFL++ 插桩模式）。

    执行手册：「针对 Agent B 报告的漏洞函数，编译插桩版本」

    Args:
        source_root: 容器内源码根目录（通常为 /sentinel-work/target）
        vuln_file:   Agent B 发现的漏洞所在文件（相对路径，可选）

    Returns:
        bash 脚本字符串
    """
    script = f"""#!/bin/bash
set -e
cd /sentinel-work/target

echo "[SENTINEL] 开始 AFL++ 插桩编译..."

# 优先尝试 cmake 构建
if [ -f CMakeLists.txt ]; then
    echo "[SENTINEL] 检测到 CMakeLists.txt，使用 cmake 编译"
    mkdir -p /sentinel-work/build
    cd /sentinel-work/build
    CC=afl-clang-fast CXX=afl-clang-fast++ cmake /sentinel-work/target -DCMAKE_BUILD_TYPE=Debug
    make -j$(nproc)
    BINARY=$(find /sentinel-work/build -maxdepth 2 -type f -executable | head -1)

# 尝试 Makefile 构建
elif [ -f Makefile ] || [ -f makefile ]; then
    echo "[SENTINEL] 检测到 Makefile，使用 make 编译"
    CC=afl-clang-fast CXX=afl-clang-fast++ make -j$(nproc) -C /sentinel-work/target
    BINARY=$(find /sentinel-work/target -maxdepth 2 -type f -executable | head -1)

# 退路：直接编译所有 .c 文件
else
    echo "[SENTINEL] 未发现构建系统，直接编译所有 .c 文件"
    C_FILES=$(find /sentinel-work/target -name "*.c" | head -20 | tr '\\n' ' ')
    if [ -z "$C_FILES" ]; then
        C_FILES=$(find /sentinel-work/target -name "*.cpp" | head -20 | tr '\\n' ' ')
        afl-clang-fast++ -o /sentinel-work/build/target_bin $C_FILES -g -fsanitize=address 2>&1
    else
        afl-clang-fast -o /sentinel-work/build/target_bin $C_FILES -g -fsanitize=address 2>&1
    fi
    BINARY=/sentinel-work/build/target_bin
fi

# 复制二进制到标准位置
if [ -n "$BINARY" ] && [ -f "$BINARY" ]; then
    cp "$BINARY" /sentinel-work/build/target_bin
    chmod +x /sentinel-work/build/target_bin
    echo "[SENTINEL] 编译成功: $BINARY"
else
    echo "[SENTINEL][ERROR] 编译失败：未找到可执行文件"
    exit 1
fi

echo "[SENTINEL] 插桩编译完成，准备 AFL++ 初始种子..."
ls -la /sentinel-work/build/
"""
    return script


def _build_fuzz_script(timeout_secs: int = 300) -> str:
    """
    生成 AFL++ 模糊测试启动脚本。

    执行手册：「运行 5 分钟，收集崩溃样本」

    Args:
        timeout_secs: AFL++ 运行时间限制（秒）
    """
    script = f"""#!/bin/bash
echo "[SENTINEL] 启动 AFL++ 模糊测试，运行时间限制: {timeout_secs}s"

# AFL++ 配置参数
export AFL_SKIP_CPUFREQ=1
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
export AFL_NO_UI=1

# 如果没有用户种子，使用容器内置种子
if [ ! "$(ls -A /sentinel-work/seeds/)" ]; then
    echo "SENTINEL_SEED" > /sentinel-work/seeds/default.txt
fi

# 运行 AFL++
# -i: 输入种子目录
# -o: 崩溃输出目录
# -V: 最大运行时间（秒）
# @@: 表示目标程序从文件读取输入
timeout {timeout_secs} afl-fuzz \\
    -i /sentinel-work/seeds \\
    -o /sentinel-work/findings \\
    -V {timeout_secs} \\
    -- /sentinel-work/build/target_bin @@ \\
    > /sentinel-work/logs/afl.log 2>&1 || true

echo "[SENTINEL] AFL++ 运行结束"
echo "[SENTINEL] 崩溃样本数量: $(ls /sentinel-work/findings/default/crashes/ 2>/dev/null | grep -c 'id:' || echo 0)"
"""
    return script


def _parse_afl_crashes(container, findings_path: str = "/sentinel-work/findings") -> tuple[bool, str]:
    """
    从容器内提取 AFL++ 崩溃文件内容。

    Returns:
        (crash_found: bool, crash_log: str)
    """
    try:
        # 检查 crashes 目录是否存在且有文件
        exit_code, output = container.exec_run(
            f"sh -c 'ls {findings_path}/default/crashes/ 2>/dev/null | grep -c id: || echo 0'",
            demux=False,
        )
        crash_count_str = output.decode("utf-8", errors="replace").strip() if output else "0"
        crash_count = int(crash_count_str) if crash_count_str.isdigit() else 0

        if crash_count == 0:
            logger.info("[Sandbox] AFL++ 未发现崩溃")
            return False, ""

        # 读取 AFL++ 的运行日志
        exit_code, afl_log_raw = container.exec_run(
            "cat /sentinel-work/logs/afl.log",
            demux=False,
        )
        afl_log = afl_log_raw.decode("utf-8", errors="replace") if afl_log_raw else ""

        # 读取第一个崩溃文件内容（十六进制）
        exit_code, crash_raw = container.exec_run(
            f"sh -c 'CRASH=$(ls {findings_path}/default/crashes/id:* 2>/dev/null | head -1); "
            f"if [ -n \"$CRASH\" ]; then xxd \"$CRASH\" 2>/dev/null | head -20; fi'",
            demux=False,
        )
        crash_hex = crash_raw.decode("utf-8", errors="replace") if crash_raw else ""

        crash_log = (
            f"[AFL++] 发现 {crash_count} 个崩溃样本\n"
            f"[AFL++] 运行日志:\n{afl_log[:3000]}\n"
            f"[AFL++] 首个崩溃输入（十六进制）:\n{crash_hex}"
        )

        logger.info(f"[Sandbox] AFL++ 发现 {crash_count} 个崩溃")
        return True, crash_log

    except Exception as e:
        logger.warning(f"[Sandbox] 解析 AFL++ 崩溃文件失败: {e}")
        return False, ""


def _parse_ebpf_log(container, log_path: str = "/sentinel-work/logs/ebpf.log") -> list[dict]:
    """
    从容器内提取并解析 eBPF 事件日志（JSON Lines 格式）。

    Returns:
        解析后的事件列表，每项包含 ts/event/addr/fn 等字段
    """
    events: list[dict] = []
    try:
        exit_code, raw = container.exec_run(f"cat {log_path}", demux=False)
        if not raw:
            return events

        log_text = raw.decode("utf-8", errors="replace")
        for line in log_text.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                evt = json.loads(line)
                # 只保留关键安全事件，跳过 malloc/heartbeat 等噪声
                if evt.get("event") in ("double_free", "use_after_free", "heap_overflow",
                                        "null_deref", "stack_overflow", "out_of_bounds"):
                    events.append(evt)
            except json.JSONDecodeError:
                pass

        logger.info(f"[Sandbox] 解析 eBPF 日志：发现 {len(events)} 个关键事件")
    except Exception as e:
        logger.warning(f"[Sandbox] 读取 eBPF 日志失败: {e}")

    return events


def run_sandbox_verification(
    task_db_id: str,
    source_path: str,
    sandbox_image: str = "sentinel-sandbox:latest",
    timeout_secs: int = 360,
    cpu_quota: int = 1_000_000_000,
    mem_limit: str = "1g",
) -> SandboxResult:
    """
    执行完整的 Docker 沙箱动态验证生命周期。

    !! 注意：此函数是同步阻塞的，必须在 asyncio.to_thread() 中调用 !!

    生命周期：
      1. 拉起容器（特权模式 + 资源限制 + 卷挂载）
      2. 编译源码（AFL++ 插桩）
      3. 后台启动 eBPF 监控
      4. 运行 AFL++ 模糊测试
      5. 提取日志（AFL++ crashes + eBPF events）
      6. finally 强制销毁容器

    Args:
        task_db_id:    PostgreSQL task.id 字符串（用于容器命名，防止冲突）
        source_path:   宿主机上的源码目录或 ZIP 文件路径
        sandbox_image: Docker 镜像名称
        timeout_secs:  整体超时秒数（默认 6 分钟）
        cpu_quota:     CPU 限制（nano_cpus）
        mem_limit:     内存限制字符串（如 "1g"）

    Returns:
        SandboxResult 对象
    """
    import docker
    from docker.errors import DockerException, NotFound

    result = SandboxResult()
    container = None
    start_time = time.time()

    # 容器唯一名称（使用 task_id 前 8 位，防止同名冲突）
    container_name = f"sentinel_fuzzer_{task_db_id[:8]}"

    # 确保 source_path 是目录（如果是 ZIP，应在上游任务中已解压）
    source_abs = str(Path(source_path).resolve())
    if not Path(source_abs).exists():
        result.error = f"源码路径不存在: {source_abs}"
        logger.error(f"[Sandbox] {result.error}")
        return result

    logger.info(
        f"[Sandbox] 启动沙箱验证 task={task_db_id}, image={sandbox_image}, "
        f"source={source_abs}, timeout={timeout_secs}s"
    )

    try:
        client = _get_docker_client()

        # ── 拉起容器 ─────────────────────────────────────────────────────────
        container = client.containers.run(
            image=sandbox_image,
            name=container_name,
            # 特权模式：eBPF uprobe 需要 CAP_SYS_ADMIN（执行手册要求）
            privileged=True,
            # 资源限制（防止 Fuzzing 耗尽宿主机资源）
            nano_cpus=cpu_quota,
            mem_limit=mem_limit,
            # 数据卷：将宿主机源码目录挂载到容器内（只读）
            volumes={
                source_abs: {
                    "bind": "/sentinel-work/target",
                    "mode": "ro",       # 只读，防止沙箱污染源码
                },
            },
            # 使容器保持运行（等待我们发送命令）
            detach=True,
            stdin_open=True,
            tty=False,
            # 自动挂载 eBPF 相关文件系统（必须）
            security_opt=["seccomp=unconfined"],
        )

        logger.info(f"[Sandbox] 容器已启动: {container.id[:12]}")

        # ── 步骤 1: 编译源码（AFL++ 插桩）────────────────────────────────────
        compile_script = _build_compile_script("/sentinel-work/target")
        logger.info("[Sandbox] 开始插桩编译...")

        # 写入编译脚本到容器
        exit_code, output = container.exec_run(
            ["bash", "-c", compile_script],
            demux=False,
            workdir="/sentinel-work",
        )
        compile_output = output.decode("utf-8", errors="replace") if output else ""
        logger.info(f"[Sandbox] 编译完成 (exit={exit_code}):\n{compile_output[-500:]}")

        if exit_code != 0:
            result.error = f"编译失败 (exit_code={exit_code}): {compile_output[-300:]}"
            logger.error(f"[Sandbox] {result.error}")
            return result

        # ── 步骤 2: 后台启动 eBPF 监控脚本 ──────────────────────────────────
        logger.info("[Sandbox] 启动 eBPF uprobe 监控...")
        # 获取目标二进制的 PID（先以测试模式运行一次拿到 PID，再挂载 eBPF）
        # 实际场景：先后台运行目标程序，再挂载 eBPF；或者用 bpftrace 的 -p 参数
        # 此处直接挂载到 target_bin，bpftrace 会在首次调用时激活
        ebpf_cmd = (
            "nohup bpftrace /sentinel-ebpf/monitor.bt "
            "> /sentinel-work/logs/ebpf.log 2>&1 &"
        )
        container.exec_run(
            ["bash", "-c", ebpf_cmd],
            detach=True,    # 后台运行，不等待结果
        )
        logger.info("[Sandbox] eBPF 监控已后台启动")
        time.sleep(2)  # 等待 bpftrace 完成 uprobe 挂载

        # ── 步骤 3: 运行 AFL++ 模糊测试 ──────────────────────────────────────
        afl_timeout = max(60, timeout_secs - 60)  # 预留 60s 给编译和日志提取
        fuzz_script = _build_fuzz_script(afl_timeout)
        logger.info(f"[Sandbox] 开始 AFL++ Fuzzing，时间限制: {afl_timeout}s")

        exec_result = container.exec_run(
            ["bash", "-c", fuzz_script],
            demux=False,
            workdir="/sentinel-work",
        )
        fuzz_output = exec_result.output.decode("utf-8", errors="replace") if exec_result.output else ""
        logger.info(f"[Sandbox] AFL++ Fuzzing 完成 (exit={exec_result.exit_code})")

        # ── 步骤 4: 提取 AFL++ 崩溃日志 ─────────────────────────────────────
        crash_found, crash_log = _parse_afl_crashes(container)
        result.crash_found = crash_found
        result.afl_crash_log = crash_log

        # ── 步骤 5: 提取 eBPF 事件日志 ───────────────────────────────────────
        result.ebpf_events = _parse_ebpf_log(container)

        # ── 步骤 6: 读取 AFL++ 统计数据 ──────────────────────────────────────
        try:
            exit_code, stats_raw = container.exec_run(
                "cat /sentinel-work/findings/default/fuzzer_stats",
                demux=False,
            )
            if stats_raw:
                for line in stats_raw.decode("utf-8", errors="replace").splitlines():
                    if ":" in line:
                        key, _, val = line.partition(":")
                        result.afl_stats[key.strip()] = val.strip()
        except Exception:
            pass

    except Exception as e:
        result.error = str(e)
        result.timed_out = "timeout" in str(e).lower() or "timed out" in str(e).lower()
        logger.error(f"[Sandbox] 验证过程异常 task={task_db_id}: {e}", exc_info=True)

    finally:
        # !! 核心防御机制：无论发生什么，一定要销毁容器 !!
        elapsed = time.time() - start_time
        result.elapsed_seconds = elapsed

        if container is not None:
            try:
                logger.info(f"[Sandbox] 正在销毁容器 {container_name}...")
                container.stop(timeout=10)
                container.remove(force=True)
                logger.info(f"[Sandbox] 容器 {container_name} 已销毁 (运行时长: {elapsed:.1f}s)")
            except Exception as cleanup_err:
                logger.error(f"[Sandbox] 容器销毁失败: {cleanup_err}")

    return result


def force_kill_container(task_db_id: str) -> bool:
    """
    强制销毁指定 task_id 对应的沙箱容器。
    供 cancel 接口调用（紧急中断 Fuzzing 任务）。

    Args:
        task_db_id: PostgreSQL task.id 字符串

    Returns:
        True 表示成功销毁，False 表示容器不存在或已销毁
    """
    import docker
    from docker.errors import NotFound

    container_name = f"sentinel_fuzzer_{task_db_id[:8]}"
    try:
        client = _get_docker_client()
        container = client.containers.get(container_name)
        container.stop(timeout=5)
        container.remove(force=True)
        logger.info(f"[Sandbox] 强制销毁容器 {container_name} 成功")
        return True
    except NotFound:
        logger.info(f"[Sandbox] 容器 {container_name} 不存在或已销毁")
        return False
    except Exception as e:
        logger.error(f"[Sandbox] 强制销毁容器 {container_name} 失败: {e}")
        return False
