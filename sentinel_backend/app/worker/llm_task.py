import asyncio
import base64
import json
import logging
import uuid
from pathlib import Path

import httpx

from app.core.broker import broker
from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.core.ws_manager import ws_manager
from app.models.vulnerability import Vulnerability, VerifyStatus

logger = logging.getLogger(__name__)

_SUPPORTED_TARGETS = {
    "buffer-overflow",
    "heap-overflow",
    "stack-overflow",
    "heap-buffer-overflow",
    "stack-buffer-overflow",
    "possible-buffer-overflow",
    "use-after-free",
    "uaf",
    "double-free",
    "cwe-120",
    "cwe-121",
    "cwe-122",
    "cwe-415",
    "cwe-416",
}


_MOCK_AGENT_B_RESPONSE = {
    "vulnerabilities": [
        {
            "vuln_type": "Use-After-Free",
            "file_path": "src/ssl/ssl_lib.c",
            "line_number": 1234,
            "code_context": (
                "1231: char *buf = malloc(len);\n"
                "1232: process(buf);\n"
                "1233: free(buf);\n"
                "1234: memcpy(out, buf, len);  /* buf is used after free */\n"
                "1235: return len;\n"
            ),
            "trigger_cond": "Mock UAF finding used when ML_MOCK_MODE=true.",
            "fix_advice": "Set the pointer to NULL after free and guard later uses. [MOCK DATA]",
        },
        {
            "vuln_type": "Heap_Overflow",
            "file_path": "src/crypto/mem.c",
            "line_number": 89,
            "code_context": (
                "87: char *dst = malloc(n);\n"
                "88: // n is externally controlled\n"
                "89: memcpy(dst, src, n + extra_bytes);  /* overflow */\n"
                "90: return dst;\n"
            ),
            "trigger_cond": "Mock heap overflow finding used when ML_MOCK_MODE=true.",
            "fix_advice": "Validate copy size against the allocated destination size. [MOCK DATA]",
        },
    ],
    "agent_e": {"harness_packages": []},
}


async def _call_agent_b(
    source_root: str,
    cpp_files: list[str],
    target_vulns: list[str] | None = None,
) -> dict:
    if settings.ML_MOCK_MODE:
        logger.info("[LLM] ML_MOCK_MODE=true, using built-in Agent B demo data instead of the external agent service")
        await asyncio.sleep(2)
        return _MOCK_AGENT_B_RESPONSE

    request_body = {
        "source_root": source_root,
        "cpp_files": cpp_files,
        "target_vulns": target_vulns or [],
        "generate_harness": True,
    }

    logger.info(f"[LLM] ML_MOCK_MODE=false, calling Agent B endpoint: {settings.ML_AGENT_B_URL}")
    try:
        async with httpx.AsyncClient(timeout=900.0) as client:
            resp = await client.post(settings.ML_AGENT_B_URL, json=request_body)
            resp.raise_for_status()
            return resp.json()
    except httpx.TimeoutException:
        logger.error("[LLM] Agent B call timed out")
        raise
    except httpx.HTTPStatusError as exc:
        logger.error(
            "[LLM] Agent B returned HTTP %s: %s",
            exc.response.status_code,
            exc.response.text[:500],
        )
        raise
    except Exception as exc:
        logger.error(f"[LLM] Agent B call failed: {exc}", exc_info=True)
        raise


def _normalize_target(value: str) -> str:
    return str(value or "").strip().lower().replace("_", "-").replace(" ", "-")


def _parse_target_vulns(raw: str) -> list[str]:
    if not raw:
        return []

    parsed_items: list[str] = []
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, list):
            parsed_items = [str(item) for item in parsed]
        elif isinstance(parsed, str):
            parsed_items = [parsed]
    except Exception:
        stripped = raw.strip().strip("[]")
        parsed_items = [
            item.strip().strip("'\"")
            for item in stripped.split(",")
            if item.strip().strip("'\"")
        ]
        logger.warning(
            "[LLM] target_vulns_json was not strict JSON, parsed permissively: %r -> %s",
            raw,
            parsed_items,
        )

    valid_items = [
        item for item in parsed_items
        if _normalize_target(item) in _SUPPORTED_TARGETS
    ]
    if parsed_items and not valid_items:
        logger.warning(
            "[LLM] ignoring invalid target_vulns=%s; auditing all supported vulnerability types",
            parsed_items,
        )
    return valid_items


async def _broadcast_llm_progress(
    task_db_id: str,
    message: str,
    log_stream: str,
    percent: int = 60,
) -> None:
    await ws_manager.broadcast(
        task_db_id,
        {
            "stage": "llm",
            "percent": percent,
            "message": message,
            "log_stream": log_stream,
        },
    )


async def _save_vulnerabilities(task_db_id: str, vulns: list[dict]) -> dict:
    """
    Persist backend vulnerability rows and keep Agent finding_id attribution.
    """
    if not vulns:
        logger.info(f"[LLM] task={task_db_id} Agent B returned no vulnerabilities")
        return {"vuln_ids": [], "finding_id_to_vuln_id": {}}

    async with AsyncSessionLocal() as session:
        records = []
        finding_id_to_record = {}

        for item in vulns:
            record = Vulnerability(
                task_id=uuid.UUID(task_db_id),
                vuln_type=item.get("vuln_type", "Unknown"),
                file_path=item.get("file_path"),
                line_number=item.get("line_number"),
                code_context=item.get("code_context"),
                trigger_cond=item.get("trigger_cond"),
                fix_advice=item.get("fix_advice"),
                verify_status=VerifyStatus.UNVERIFIED,
            )
            records.append(record)
            finding_id = item.get("finding_id")
            if finding_id:
                finding_id_to_record[str(finding_id)] = record

        session.add_all(records)
        await session.flush()

        vuln_ids = [str(record.id) for record in records]
        finding_id_to_vuln_id = {
            finding_id: str(record.id)
            for finding_id, record in finding_id_to_record.items()
        }
        await session.commit()

    logger.info(f"[LLM] task={task_db_id} saved {len(vuln_ids)} vulnerabilities")
    return {"vuln_ids": vuln_ids, "finding_id_to_vuln_id": finding_id_to_vuln_id}


def _persist_harness_bundles(
    task_db_id: str,
    agent_b_result: dict,
    finding_id_to_vuln_id: dict[str, str],
) -> str | None:
    """
    Materialize Agent E harness packages into backend-owned storage.

    Agent service package paths are not portable across containers. The agent
    embeds file contents in the response; the worker recreates those packages
    under uploads/harness_bundles so the sandbox can mount and execute them.
    """
    packages = (agent_b_result.get("agent_e") or {}).get("harness_packages", [])
    if not packages:
        logger.info(f"[LLM] task={task_db_id} no harness packages returned")
        return None

    bundle_root = Path("uploads") / "harness_bundles" / task_db_id
    bundle_root.mkdir(parents=True, exist_ok=True)

    manifest_packages = []
    for idx, package in enumerate(packages, start=1):
        package_id = str(package.get("package_id") or f"HARNESS-{idx:04d}")
        package_dir = bundle_root / package_id
        seeds_dir = package_dir / "seeds"
        findings_dir = package_dir / "findings"
        seeds_dir.mkdir(parents=True, exist_ok=True)
        findings_dir.mkdir(parents=True, exist_ok=True)

        for name, content in (package.get("embedded_files") or {}).items():
            (package_dir / Path(name).name).write_text(str(content), encoding="utf-8")

        for name, content_b64 in (package.get("embedded_seed_files_b64") or {}).items():
            try:
                payload = base64.b64decode(content_b64)
            except Exception:
                payload = b"default_seed"
            (seeds_dir / Path(name).name).write_bytes(payload)

        harness_config = package_dir / "harness_config.json"
        if not harness_config.exists():
            harness_config.write_text(
                json.dumps(package, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )

        finding_id = str(package.get("finding_id") or "")
        manifest_packages.append({
            "package_id": package_id,
            "finding_id": finding_id,
            "vuln_id": finding_id_to_vuln_id.get(finding_id),
            "cwe_id": package.get("cwe_id"),
            "target_file": package.get("target_file"),
            "target_function": package.get("target_function"),
            "package_dir": str(package_dir.resolve()),
        })

    manifest = {
        "task_id": task_db_id,
        "bundle_root": str(bundle_root.resolve()),
        "packages": manifest_packages,
    }
    (bundle_root / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    logger.info(
        "[LLM] task=%s materialized %s harness packages at %s",
        task_db_id,
        len(manifest_packages),
        bundle_root,
    )
    return str(bundle_root.resolve())


@broker.task(
    task_name="llm_audit",
    max_retries=1,
    retry_on_error=True,
)
async def run_llm_audit(
    task_db_id: str,
    source_path: str,
    is_dynamic: bool = False,
    target_vulns_json: str = "",
) -> dict:
    logger.info(f"[LLM] Starting audit task={task_db_id}, source={source_path}")

    if not Path(source_path).is_absolute():
        source_path = str(Path(source_path).resolve())

    if source_path.endswith(".zip") and Path(source_path).is_file():
        from app.services.source_parser import parse_zip_source

        ctx = await asyncio.to_thread(parse_zip_source, source_path)
        source_path = ctx.source_root

    cpp_extensions = {".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".hh"}
    cpp_files: list[str] = []
    source_root = Path(source_path)
    if source_root.is_dir():
        for file_path in source_root.rglob("*"):
            if file_path.is_file() and file_path.suffix.lower() in cpp_extensions:
                cpp_files.append(str(file_path.relative_to(source_root)))
        logger.info(f"[LLM] task={task_db_id} found {len(cpp_files)} C/C++ files")
        await _broadcast_llm_progress(
            task_db_id,
            "Static audit source scan completed.",
            f"[LLM] Found {len(cpp_files)} C/C++ source files.\n",
            percent=62,
        )
    else:
        logger.warning(f"[LLM] source_path is not a directory: {source_path}")

    target_vulns = _parse_target_vulns(target_vulns_json)
    await _broadcast_llm_progress(
        task_db_id,
        "Calling Agent B static audit service.",
        f"[LLM] Target vulnerability filter: {target_vulns or 'all'}.\n"
        f"[LLM] Calling Agent B endpoint: {settings.ML_AGENT_B_URL}\n",
        percent=64,
    )

    agent_b_result = await _call_agent_b(source_path, cpp_files, target_vulns)
    vulns = agent_b_result.get("vulnerabilities", [])
    await _broadcast_llm_progress(
        task_db_id,
        "Agent B static audit completed.",
        f"[LLM] Agent B returned {len(vulns)} vulnerabilities.\n",
        percent=68,
    )

    saved = await _save_vulnerabilities(task_db_id, vulns)
    harness_bundle_root = _persist_harness_bundles(
        task_db_id=task_db_id,
        agent_b_result=agent_b_result,
        finding_id_to_vuln_id=saved["finding_id_to_vuln_id"],
    )

    result = {
        "vulns_found": len(saved["vuln_ids"]),
        "vuln_ids": saved["vuln_ids"],
        "harness_bundle_root": harness_bundle_root,
    }
    logger.info(f"[LLM] task={task_db_id} audit completed: {result}")

    if is_dynamic:
        from app.worker.pipeline import trigger_fuzzing_stage

        await trigger_fuzzing_stage(
            task_db_id=task_db_id,
            source_path=source_path,
            harness_bundle_root=harness_bundle_root,
        )
    else:
        from app.worker.pipeline import finalize_task_no_fuzzing

        await finalize_task_no_fuzzing.kiq(task_db_id)

    return result
