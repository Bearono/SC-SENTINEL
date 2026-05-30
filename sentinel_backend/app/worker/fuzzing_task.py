"""
阶段三任务：Docker 沙箱动态验证（AFL++ + eBPF）
──────────────────────────────────────────────────────────────────────────────
执行手册第 2.3 节、阶段三任务清单第 4 点：

  在 Taskiq 异步任务中调用 sandbox_manager 完成完整验证生命周期：
    1. 调用 sandbox_manager.run_sandbox_verification()（在线程池中阻塞运行）
    2. 将 SandboxResult 写入数据库：
       - 更新 vulnerability.verify_status = CONFIRMED / FALSE_POSITIVE
       - 更新 vulnerability.afl_log = AFL++ 崩溃日志
       - 批量写入 ebpf_event_log 表（eBPF 捕获的内核事件）
    3. 将 Task 状态更新为 COMPLETED
    4. 广播最终完成消息到 WebSocket

关键防御机制（执行手册 + 任务清单第 3 点）：
  - asyncio.wait_for 超时控制：超过 SANDBOX_TIMEOUT_SECONDS 强制中断
  - sandbox_manager 内部 finally 块强制 stop + remove 容器
  - Taskiq 不重试（max_retries=0），防止容器资源泄露
"""
import asyncio
import logging
import uuid
from datetime import datetime, timezone

from app.core.broker import broker
from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.core.ws_manager import ws_manager

logger = logging.getLogger(__name__)


async def _save_fuzzing_results(
    task_db_id: str,
    sandbox_result,
) -> None:
    """
    将 SandboxResult 写入数据库：
      - 更新 vulnerability 表的验证状态和 AFL++ 日志
      - 批量插入 ebpf_event_log 表
    """
    from sqlalchemy import select
    from app.models.task import Task, TaskStatus
    from app.models.vulnerability import Vulnerability, VerifyStatus
    from app.models.ebpf_event_log import EbpfEventLog, EbpfEventType

    # ── 更新漏洞验证状态 ─────────────────────────────────────────────────────
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(Vulnerability).where(
                Vulnerability.task_id == uuid.UUID(task_db_id),
                Vulnerability.verify_status == VerifyStatus.UNVERIFIED,
            )
        )
        vulns = result.scalars().all()

        for v in vulns:
            if sandbox_result.crash_found:
                v.verify_status = VerifyStatus.CONFIRMED
                v.afl_log = sandbox_result.afl_crash_log[:5000]  # 截断防超长
            else:
                v.verify_status = VerifyStatus.FALSE_POSITIVE

        # ── 写入 eBPF 事件日志 ────────────────────────────────────────────────
        _EBPF_TYPE_MAP = {
            "double_free":     EbpfEventType.DOUBLE_FREE,
            "use_after_free":  EbpfEventType.USE_AFTER_FREE,
            "heap_overflow":   EbpfEventType.HEAP_OVERFLOW,
            "null_deref":      EbpfEventType.NULL_DEREF,
            "stack_overflow":  EbpfEventType.STACK_OVERFLOW,
            "out_of_bounds":   EbpfEventType.OUT_OF_BOUNDS,
        }

        if vulns and sandbox_result.ebpf_events:
            # 将 eBPF 事件关联到第一个漏洞（最有关联的主漏洞）
            primary_vuln_id = vulns[0].id
            for evt in sandbox_result.ebpf_events[:100]:  # 最多写入 100 条
                event_type_str = evt.get("event", "other")
                event_type = _EBPF_TYPE_MAP.get(event_type_str, EbpfEventType.OTHER)

                log = EbpfEventLog(
                    vuln_id=primary_vuln_id,
                    timestamp=int(evt.get("ts", 0)),
                    event_type=event_type,
                    function_name=evt.get("fn"),
                    memory_addr=evt.get("addr"),
                    raw_data=str(evt),
                )
                session.add(log)

        await session.commit()
        logger.info(
            f"[Fuzzing] task={task_db_id} 写入 {len(vulns)} 条漏洞验证状态, "
            f"{len(sandbox_result.ebpf_events)} 条 eBPF 事件"
        )

    # ── 更新 Task 状态为 COMPLETED ───────────────────────────────────────────
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(Task).where(Task.id == uuid.UUID(task_db_id))
        )
        task = result.scalar_one_or_none()
        if task and task.status not in (TaskStatus.FAILED, TaskStatus.COMPLETED):
            task.status = TaskStatus.COMPLETED
            task.completed_at = datetime.now(timezone.utc)
            await session.commit()
            logger.info(f"[Fuzzing] task={task_db_id} 状态更新为 COMPLETED")


@broker.task(
    task_name="dynamic_fuzzing",
    max_retries=0,        # Fuzzing 不重试（防止容器资源泄露）
    retry_on_error=False,
)
async def run_dynamic_fuzzing(task_db_id: str, source_path: str) -> dict:
    """
    Docker 沙箱动态验证任务（阶段三）。

    执行步骤：
      1. 在线程池中运行同步的 sandbox_manager（Docker SDK 是同步阻塞库）
      2. asyncio.wait_for 超时控制（配置项 SANDBOX_TIMEOUT_SECONDS）
      3. 写入验证结果到数据库
      4. 广播最终完成进度到 WebSocket

    Labels（由 pipeline.trigger_fuzzing_stage 注入）：
      task_db_id : str → PostgreSQL task.id
      stage      : "fuzzing"

    Returns:
        dict: {"crash_found": bool, "ebpf_events": int, "elapsed_seconds": float}
    """
    from app.services.sandbox_manager import run_sandbox_verification, SandboxResult

    logger.info(f"[Fuzzing] 开始动态验证 task={task_db_id}, source={source_path}")

    sandbox_result: SandboxResult = SandboxResult()

    try:
        # ── 关键：asyncio.wait_for 超时 + asyncio.to_thread 线程池隔离 ────────
        # Docker SDK (docker-py) 是完全同步阻塞的库，
        # 必须放在 to_thread() 里执行，避免阻塞 TaskIQ Worker 的事件循环。
        # 同时用 wait_for 设置总超时，超时后抛出 asyncio.TimeoutError。
        sandbox_result = await asyncio.wait_for(
            asyncio.to_thread(
                run_sandbox_verification,
                task_db_id=task_db_id,
                source_path=source_path,
                sandbox_image=settings.SANDBOX_IMAGE,
                timeout_secs=settings.SANDBOX_TIMEOUT_SECONDS,
                cpu_quota=settings.SANDBOX_CPU_QUOTA,
                mem_limit=settings.SANDBOX_MEM_LIMIT,
            ),
            timeout=settings.SANDBOX_TIMEOUT_SECONDS + 60,  # 额外 60s 给清理流程
        )

    except asyncio.TimeoutError:
        logger.error(f"[Fuzzing] task={task_db_id} 沙箱验证超时 ({settings.SANDBOX_TIMEOUT_SECONDS}s)")
        sandbox_result.timed_out = True
        sandbox_result.error = f"沙箱验证超时（超过 {settings.SANDBOX_TIMEOUT_SECONDS}s）"
        # 注意：sandbox_manager 内部的 finally 块会负责销毁容器，无需在此重复

    except Exception as e:
        logger.error(f"[Fuzzing] task={task_db_id} 沙箱验证异常: {e}", exc_info=True)
        sandbox_result.error = str(e)

    # ── 将结果写入数据库 ─────────────────────────────────────────────────────
    try:
        await _save_fuzzing_results(task_db_id, sandbox_result)
    except Exception as e:
        logger.error(f"[Fuzzing] task={task_db_id} 写入数据库失败: {e}", exc_info=True)

    # ── 广播最终完成消息 ─────────────────────────────────────────────────────
    if sandbox_result.error and not sandbox_result.crash_found:
        # 沙箱出现错误（但未崩溃也算）
        final_msg = (
            f"⚠️ 动态验证完成（{'超时' if sandbox_result.timed_out else '异常'}）"
            f"：{sandbox_result.error[:100]}"
        )
    elif sandbox_result.crash_found:
        ebpf_count = len(sandbox_result.ebpf_events)
        final_msg = (
            f"🎉 动态验证完成！发现崩溃证据！"
            f"eBPF 捕获 {ebpf_count} 个内核事件，漏洞已确认（CONFIRMED）。"
        )
    else:
        final_msg = (
            f"✅ 动态验证完成，运行时长 {sandbox_result.elapsed_seconds:.1f}s。"
            f"未触发崩溃（漏洞可能需要特定触发条件）。"
        )

    await ws_manager.broadcast(
        task_db_id,
        {
            "stage":      "done",
            "percent":    100,
            "message":    final_msg,
            "log_stream": sandbox_result.afl_crash_log[:2000],
        },
    )

    result_summary = {
        "crash_found":     sandbox_result.crash_found,
        "ebpf_events":     len(sandbox_result.ebpf_events),
        "elapsed_seconds": sandbox_result.elapsed_seconds,
        "timed_out":       sandbox_result.timed_out,
        "error":           sandbox_result.error,
    }
    logger.info(f"[Fuzzing] task={task_db_id} 动态验证完成: {result_summary}")
    return result_summary
