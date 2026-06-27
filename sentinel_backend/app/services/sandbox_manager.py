import json
import logging
import io
import shlex
import tarfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class SandboxResult:
    crash_found: bool = False
    afl_crash_log: str = ""
    ebpf_events: list[dict] = field(default_factory=list)
    elapsed_seconds: float = 0.0
    timed_out: bool = False
    error: Optional[str] = None
    afl_stats: dict = field(default_factory=dict)
    package_results: list[dict] = field(default_factory=list)


def _get_docker_client():
    import docker

    return docker.from_env()


def _container_path(path: str) -> str:
    return str(Path(path).resolve()).replace("\\", "/")


def _copy_directory_to_container(container, source_dir: str, dest_parent: str, dest_name: str) -> None:
    src = Path(source_dir).resolve()
    if not src.is_dir():
        raise ValueError(f"directory does not exist: {src}")

    container.exec_run(["bash", "-lc", f"mkdir -p {shlex.quote(dest_parent)}"], demux=False)

    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        for item in src.rglob("*"):
            arcname = str(Path(dest_name) / item.relative_to(src)).replace("\\", "/")
            tar.add(str(item), arcname=arcname, recursive=False)
    buffer.seek(0)
    container.put_archive(dest_parent, buffer.getvalue())


def _parse_json_lines(text: str) -> list[dict]:
    events = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return events


def _read_container_text(container, path: str, max_chars: int = 20000) -> str:
    exit_code, raw = container.exec_run(["bash", "-lc", f"cat {path} 2>/dev/null || true"], demux=False)
    if not raw:
        return ""
    return raw.decode("utf-8", errors="replace")[-max_chars:]


def _parse_afl_crashes(container, findings_path: str) -> tuple[bool, str, dict]:
    count_cmd = f"ls {findings_path}/default/crashes/id:* 2>/dev/null | wc -l"
    _, raw_count = container.exec_run(["bash", "-lc", count_cmd], demux=False)
    count_text = raw_count.decode("utf-8", errors="replace").strip() if raw_count else "0"
    try:
        crash_count = int(count_text)
    except ValueError:
        crash_count = 0

    afl_log = _read_container_text(container, f"{findings_path}/../logs/afl.log")
    stats_text = _read_container_text(container, f"{findings_path}/default/fuzzer_stats")
    stats = {}
    for line in stats_text.splitlines():
        if ":" in line:
            key, _, value = line.partition(":")
            stats[key.strip()] = value.strip()

    if crash_count <= 0:
        return False, afl_log, stats

    _, crash_hex_raw = container.exec_run(
        ["bash", "-lc", f"CRASH=$(ls {findings_path}/default/crashes/id:* | head -1); xxd \"$CRASH\" 2>/dev/null | head -30"],
        demux=False,
    )
    crash_hex = crash_hex_raw.decode("utf-8", errors="replace") if crash_hex_raw else ""
    crash_log = (
        f"[AFL++] crash_count={crash_count}\n"
        f"[AFL++] log:\n{afl_log[:5000]}\n"
        f"[AFL++] first crash input hex:\n{crash_hex}"
    )
    return True, crash_log, stats


def _run_format_string_probe(container, package_dir: str, logs_dir: str) -> tuple[list[dict], str]:
    """
    CWE-134 often proves reachability through formatted output instead of a
    crash. Run the generated seeds once and look for printf-style expansion.
    """
    probe_cmd = f"""
cd {package_dir}
rm -f {logs_dir}/format_probe.log
for seed in seeds/*; do
  [ -f "$seed" ] || continue
  echo "=== seed:$(basename "$seed") ===" >> {logs_dir}/format_probe.log
  echo "--- input ---" >> {logs_dir}/format_probe.log
  xxd -p "$seed" | head -5 >> {logs_dir}/format_probe.log
  echo "--- output ---" >> {logs_dir}/format_probe.log
  timeout 3 ./afl_target "$seed" >> {logs_dir}/format_probe.log 2>&1
  echo "--- rc:$? ---" >> {logs_dir}/format_probe.log
done
"""
    container.exec_run(["bash", "-lc", probe_cmd], demux=False)
    text = _read_container_text(container, f"{logs_dir}/format_probe.log", max_chars=12000)

    evidence = []
    lower = text.lower()
    expanded_pointer = "0x" in lower and "%p" not in lower.split("--- output ---")[-1]
    expanded_hex = any(token in lower for token in ("fmt:", "252x", "2578")) and "%x" not in lower.split("--- output ---")[-1]
    percent_n_crash = "seed_003_write_probe" in lower and "--- rc:0 ---" not in lower

    if expanded_pointer or expanded_hex or percent_n_crash:
        evidence.append({
            "ts": int(time.time_ns()),
            "event": "format_string_suspected",
            "fn": "printf-family",
            "addr": None,
            "severity": "high",
            "source": "direct_seed_probe",
            "detail": "Generated CWE-134 seed produced formatted-output or %n crash evidence.",
        })
    return evidence, text


def _run_asan_seed_probe(container, package_dir: str, logs_dir: str) -> tuple[bool, str]:
    """
    Generated seeds are often intentionally crashing proof-of-concept inputs.
    AFL++ treats crashing initial seeds as invalid corpus entries and may not
    save them under findings/default/crashes, so run an ASan replay first and
    use sanitizer output as direct dynamic evidence.
    """
    probe_cmd = f"""
cd {package_dir}
rm -f {logs_dir}/asan_probe.log
for seed in seeds/*; do
  [ -f "$seed" ] || continue
  echo "=== seed:$(basename "$seed") ===" >> {logs_dir}/asan_probe.log
  ASAN_OPTIONS=abort_on_error=1:symbolize=1 timeout 5 ./asan_target "$seed" >> {logs_dir}/asan_probe.log 2>&1
  rc=$?
  echo "--- rc:$rc ---" >> {logs_dir}/asan_probe.log
done
"""
    container.exec_run(["bash", "-lc", probe_cmd], demux=False)
    text = _read_container_text(container, f"{logs_dir}/asan_probe.log", max_chars=20000)
    lower = text.lower()
    crash_markers = (
        "error: addresssanitizer",
        "heap-buffer-overflow",
        "stack-buffer-overflow",
        "heap-use-after-free",
        "double-free",
        "attempting free on address",
    )
    return any(marker in lower for marker in crash_markers), text


def _start_ebpf_for_pid(container, pid: str, log_path: str) -> None:
    mount_cmd = """
mkdir -p /sys/kernel/debug /sys/kernel/debug/tracing /sys/kernel/tracing 2>/dev/null || true
mount -t debugfs debugfs /sys/kernel/debug 2>/dev/null || true
mount -t tracefs tracefs /sys/kernel/tracing 2>/dev/null || true
mount -t tracefs tracefs /sys/kernel/debug/tracing 2>/dev/null || true
"""
    container.exec_run(["bash", "-lc", mount_cmd], demux=False)

    # monitor.bt reads $1, so the PID must be passed as a positional argument.
    cmd = f"nohup bpftrace /sentinel-ebpf/monitor.bt {pid} > {log_path} 2>&1 & echo $!"
    container.exec_run(["bash", "-lc", cmd], demux=False)
    time.sleep(2)


def _stop_ebpf(container) -> None:
    container.exec_run(["bash", "-lc", "pkill -INT bpftrace 2>/dev/null || true; sleep 1"], demux=False)


def _run_harness_package(container, package: dict, timeout_secs: int) -> dict:
    package_id = package.get("package_id")
    package_dir = f"/sentinel-work/harness/{package_id}"
    logs_dir = f"{package_dir}/logs"
    findings_dir = f"{package_dir}/findings"
    ebpf_log_path = f"{logs_dir}/ebpf.log"

    result = {
        "package_id": package_id,
        "finding_id": package.get("finding_id"),
        "vuln_id": package.get("vuln_id"),
        "cwe_id": package.get("cwe_id"),
        "target_file": package.get("target_file"),
        "target_function": package.get("target_function"),
        "crash_found": False,
        "afl_crash_log": "",
        "afl_log": "",
        "runtime_evidence_log": "",
        "ebpf_events": [],
        "error": None,
    }

    target_file = str(package.get("target_file") or "")
    target_src = "/sentinel-work/target/" + target_file.replace("\\", "/").lstrip("/")
    target_root = "/sentinel-work/target"
    setup_cmd = f"""
set -e
mkdir -p {logs_dir} {findings_dir}
cd {package_dir}
make clean >/dev/null 2>&1 || true
make asan TARGET_SRC={shlex.quote(target_src)} TARGET_ROOT={shlex.quote(target_root)} > {logs_dir}/build.log 2>&1
make afl TARGET_SRC={shlex.quote(target_src)} TARGET_ROOT={shlex.quote(target_root)} >> {logs_dir}/build.log 2>&1
"""
    exit_code, raw = container.exec_run(["bash", "-lc", setup_cmd], demux=False)
    build_log = raw.decode("utf-8", errors="replace") if raw else ""
    if exit_code != 0:
        if not build_log.strip():
            build_log = _read_container_text(container, f"{logs_dir}/build.log")
        result["error"] = f"harness build failed: {build_log[-1200:]}"
        return result

    if package.get("cwe_id") == "CWE-134":
        probe_events, probe_log = _run_format_string_probe(container, package_dir, logs_dir)
        result["ebpf_events"].extend(probe_events)
        result["runtime_evidence_log"] = probe_log[-5000:]

    asan_crash, asan_log = _run_asan_seed_probe(container, package_dir, logs_dir)
    if asan_crash:
        result["crash_found"] = True
        result["afl_crash_log"] = "[ASan] generated seed replay triggered sanitizer evidence:\n" + asan_log[-12000:]
        result["runtime_evidence_log"] = (result.get("runtime_evidence_log") or "") + "\n" + asan_log[-5000:]
        return result

    afl_timeout = max(15, timeout_secs)
    fuzz_cmd = f"""
cd {package_dir}
export AFL_SKIP_CPUFREQ=1
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
export AFL_NO_UI=1
./afl_target seeds/seed_001.bin >/dev/null 2>&1 &
TARGET_PID=$!
echo $TARGET_PID > {logs_dir}/target.pid
"""
    container.exec_run(["bash", "-lc", fuzz_cmd], demux=False)

    _, raw_pid = container.exec_run(["bash", "-lc", f"cat {logs_dir}/target.pid"], demux=False)
    pid = raw_pid.decode("utf-8", errors="replace").strip() if raw_pid else ""
    if pid.isdigit():
        _start_ebpf_for_pid(container, pid, ebpf_log_path)

    run_cmd = f"""
cd {package_dir}
timeout {afl_timeout} afl-fuzz \
  -i seeds \
  -o findings \
  -V {afl_timeout} \
  -- ./afl_target @@ \
  > {logs_dir}/afl.log 2>&1 || true
"""
    container.exec_run(["bash", "-lc", run_cmd], demux=False)
    _stop_ebpf(container)

    crash_found, crash_log, stats = _parse_afl_crashes(container, findings_dir)
    ebpf_text = _read_container_text(container, ebpf_log_path)
    events = [
        evt for evt in _parse_json_lines(ebpf_text)
        if evt.get("event") not in {"monitor_start", "monitor_heartbeat", "monitor_end", "malloc", "free"}
    ]

    result["crash_found"] = crash_found
    result["afl_crash_log"] = crash_log
    result["afl_log"] = _read_container_text(container, f"{logs_dir}/afl.log")
    result["afl_stats"] = stats
    result["ebpf_events"].extend(events)
    return result


def _run_harness_bundle(
    task_db_id: str,
    source_abs: str,
    harness_bundle_root: str,
    sandbox_image: str,
    timeout_secs: int,
    package_timeout_secs: int | None,
    cpu_quota: int,
    mem_limit: str,
) -> SandboxResult:
    result = SandboxResult()
    container = None
    start_time = time.time()
    container_name = f"sentinel_harness_{task_db_id[:8]}"

    manifest_path = Path(harness_bundle_root) / "manifest.json"
    if not manifest_path.is_file():
        result.error = f"harness manifest not found: {manifest_path}"
        return result
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    packages = list(manifest.get("packages") or [])
    if not packages:
        result.error = "harness manifest contains no packages"
        return result

    try:
        client = _get_docker_client()
        container = client.containers.run(
            image=sandbox_image,
            name=container_name,
            command=["bash", "-lc", "sleep infinity"],
            privileged=True,
            nano_cpus=cpu_quota,
            mem_limit=mem_limit,
            detach=True,
            stdin_open=True,
            tty=False,
            security_opt=["seccomp=unconfined"],
        )
        _copy_directory_to_container(container, source_abs, "/sentinel-work", "target")
        _copy_directory_to_container(container, harness_bundle_root, "/sentinel-work", "harness")

        if package_timeout_secs is None:
            per_package_timeout = max(10, int(timeout_secs / max(1, len(packages))))
        else:
            per_package_timeout = max(5, package_timeout_secs)
        for package in packages:
            package_result = _run_harness_package(container, package, per_package_timeout)
            result.package_results.append(package_result)
            result.ebpf_events.extend(package_result.get("ebpf_events") or [])
            if package_result.get("crash_found"):
                result.crash_found = True
                result.afl_crash_log += "\n\n" + package_result.get("afl_crash_log", "")

    except Exception as exc:
        result.error = str(exc)
        result.timed_out = "timeout" in str(exc).lower() or "timed out" in str(exc).lower()
        logger.error("[Sandbox] harness verification failed task=%s: %s", task_db_id, exc, exc_info=True)
    finally:
        result.elapsed_seconds = time.time() - start_time
        if container is not None:
            try:
                container.stop(timeout=10)
                container.remove(force=True)
            except Exception as cleanup_err:
                logger.error("[Sandbox] failed to remove container %s: %s", container_name, cleanup_err)

    return result


def _build_legacy_compile_script() -> str:
    return """#!/bin/bash
set -e
mkdir -p /sentinel-work/build /sentinel-work/seeds /sentinel-work/findings /sentinel-work/logs
cd /sentinel-work/target
if [ -f CMakeLists.txt ]; then
  cd /sentinel-work/build
  CC=afl-clang CXX=afl-clang++ cmake /sentinel-work/target -DCMAKE_BUILD_TYPE=Debug
  make -j$(nproc)
  BINARY=$(find /sentinel-work/build -maxdepth 2 -type f -executable | head -1)
elif [ -f Makefile ] || [ -f makefile ]; then
  CC=afl-clang CXX=afl-clang++ make -j$(nproc) -C /sentinel-work/target
  BINARY=$(find /sentinel-work/target -maxdepth 2 -type f -executable | head -1)
else
  C_FILES=$(find /sentinel-work/target -name "*.c" | head -20 | tr '\\n' ' ')
  if [ -z "$C_FILES" ]; then
    CXX_FILES=$(find /sentinel-work/target -name "*.cpp" | head -20 | tr '\\n' ' ')
    afl-clang++ -o /sentinel-work/build/target_bin $CXX_FILES -g -fsanitize=address
  else
    afl-clang -o /sentinel-work/build/target_bin $C_FILES -g -fsanitize=address
  fi
  BINARY=/sentinel-work/build/target_bin
fi
if [ -n "$BINARY" ] && [ -f "$BINARY" ]; then
  cp "$BINARY" /sentinel-work/build/target_bin
  chmod +x /sentinel-work/build/target_bin
fi
"""


def _run_legacy_generic(
    task_db_id: str,
    source_abs: str,
    sandbox_image: str,
    timeout_secs: int,
    cpu_quota: int,
    mem_limit: str,
) -> SandboxResult:
    result = SandboxResult()
    container = None
    start_time = time.time()
    container_name = f"sentinel_fuzzer_{task_db_id[:8]}"

    try:
        client = _get_docker_client()
        container = client.containers.run(
            image=sandbox_image,
            name=container_name,
            command=["bash", "-lc", "sleep infinity"],
            privileged=True,
            nano_cpus=cpu_quota,
            mem_limit=mem_limit,
            detach=True,
            stdin_open=True,
            tty=False,
            security_opt=["seccomp=unconfined"],
        )
        _copy_directory_to_container(container, source_abs, "/sentinel-work", "target")

        exit_code, raw = container.exec_run(["bash", "-lc", _build_legacy_compile_script()], demux=False)
        compile_log = raw.decode("utf-8", errors="replace") if raw else ""
        if exit_code != 0:
            result.error = f"legacy compile failed: {compile_log[-1200:]}"
            return result

        container.exec_run(["bash", "-lc", "echo SENTINEL_SEED > /sentinel-work/seeds/default.txt"], demux=False)
        container.exec_run(
            ["bash", "-lc", "/sentinel-work/build/target_bin /sentinel-work/seeds/default.txt >/dev/null 2>&1 & echo $! > /sentinel-work/logs/target.pid"],
            demux=False,
        )
        _, raw_pid = container.exec_run(["bash", "-lc", "cat /sentinel-work/logs/target.pid"], demux=False)
        pid = raw_pid.decode("utf-8", errors="replace").strip() if raw_pid else ""
        if pid.isdigit():
            _start_ebpf_for_pid(container, pid, "/sentinel-work/logs/ebpf.log")

        afl_timeout = max(10, timeout_secs - 60)
        container.exec_run(
            ["bash", "-lc", f"export AFL_SKIP_CPUFREQ=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_NO_UI=1; timeout {afl_timeout} afl-fuzz -i /sentinel-work/seeds -o /sentinel-work/findings -V {afl_timeout} -- /sentinel-work/build/target_bin @@ > /sentinel-work/logs/afl.log 2>&1 || true"],
            demux=False,
        )
        _stop_ebpf(container)

        crash_found, crash_log, stats = _parse_afl_crashes(container, "/sentinel-work/findings")
        result.crash_found = crash_found
        result.afl_crash_log = crash_log
        result.afl_stats = stats
        result.ebpf_events = [
            evt for evt in _parse_json_lines(_read_container_text(container, "/sentinel-work/logs/ebpf.log"))
            if evt.get("event") not in {"monitor_start", "monitor_heartbeat", "monitor_end", "malloc", "free"}
        ]

    except Exception as exc:
        result.error = str(exc)
        result.timed_out = "timeout" in str(exc).lower() or "timed out" in str(exc).lower()
        logger.error("[Sandbox] legacy verification failed task=%s: %s", task_db_id, exc, exc_info=True)
    finally:
        result.elapsed_seconds = time.time() - start_time
        if container is not None:
            try:
                container.stop(timeout=10)
                container.remove(force=True)
            except Exception as cleanup_err:
                logger.error("[Sandbox] failed to remove container %s: %s", container_name, cleanup_err)

    return result


def run_sandbox_verification(
    task_db_id: str,
    source_path: str,
    harness_bundle_root: str | None = None,
    sandbox_image: str = "sentinel-sandbox:latest",
    timeout_secs: int = 360,
    cpu_quota: int = 1_000_000_000,
    mem_limit: str = "1g",
    package_timeout_secs: int | None = None,
) -> SandboxResult:
    source_abs = _container_path(source_path)
    if not Path(source_abs).exists():
        return SandboxResult(error=f"source path does not exist: {source_abs}")

    if harness_bundle_root and Path(harness_bundle_root).exists():
        logger.info("[Sandbox] task=%s using harness bundle: %s", task_db_id, harness_bundle_root)
        return _run_harness_bundle(
            task_db_id=task_db_id,
            source_abs=source_abs,
            harness_bundle_root=harness_bundle_root,
            sandbox_image=sandbox_image,
            timeout_secs=timeout_secs,
            package_timeout_secs=package_timeout_secs,
            cpu_quota=cpu_quota,
            mem_limit=mem_limit,
        )

    logger.info("[Sandbox] task=%s using legacy generic fuzzing path", task_db_id)
    return _run_legacy_generic(
        task_db_id=task_db_id,
        source_abs=source_abs,
        sandbox_image=sandbox_image,
        timeout_secs=timeout_secs,
        cpu_quota=cpu_quota,
        mem_limit=mem_limit,
    )


def force_kill_container(task_db_id: str) -> bool:
    from docker.errors import NotFound

    names = [
        f"sentinel_harness_{task_db_id[:8]}",
        f"sentinel_fuzzer_{task_db_id[:8]}",
    ]
    try:
        client = _get_docker_client()
        killed = False
        for name in names:
            try:
                container = client.containers.get(name)
                container.stop(timeout=5)
                container.remove(force=True)
                killed = True
            except NotFound:
                continue
        return killed
    except Exception as exc:
        logger.error("[Sandbox] force kill failed task=%s: %s", task_db_id, exc)
        return False
