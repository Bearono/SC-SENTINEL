"""
阶段二任务：LLM Multi-Agent 静态代码审计（调用 ML-B 同学的 Agent B/C 接口）
──────────────────────────────────────────────────────────────────────────────
后端职责（执行手册第 3 章）：
  1. 将解压后的源码目录路径 POST 给 ML-B 的 Agent B 接口
  2. 接收 Agent B 返回的漏洞位置列表（文件+行号+类型+触发条件+修复建议）
  3. 批量写入 vulnerability 表
  4. 根据 is_dynamic 决定是否触发沙箱动态验证阶段

接收 Agent B 返回格式（约定）：
  {
    "vulnerabilities": [
      {
        "vuln_type": "Use-After-Free",    // UAF / Heap_Overflow / Double_Free / Stack_Overflow
        "file_path": "src/ssl/ssl_lib.c",  // 相对于项目根目录
        "line_number": 1234,
        "code_context": "1232: free(buf);\\n1234: memcpy(out, buf, len);",
        "trigger_cond": "SSL 握手在特定序列下...",
        "fix_advice": "free 后立即置 NULL，使用前校验...",
      }
    ]
  }

Mock 模式（ML_MOCK_MODE=true 时）：
  跳过真实 HTTP 调用，返回标准 UAF 演示数据。
"""
import asyncio
import logging
import uuid
from pathlib import Path

import httpx

from app.core.broker import broker
from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.models.vulnerability import Vulnerability, VerifyStatus

logger = logging.getLogger(__name__)

# ── Mock 演示数据（ML_MOCK_MODE=true 时使用）─────────────────────────────────
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
                "1234: memcpy(out, buf, len);  /* ← buf 已释放，UAF 触发点 */\n"
                "1235: return len;\n"
            ),
            "trigger_cond": (
                "当 SSL 握手协议在特定序列（ClientHello → ServerHello → 提前 close_notify）"
                "下调用此函数，free(buf) 后的残留指针 buf 被 memcpy 再次解引用。"
                "[MOCK DATA]"
            ),
            "fix_advice": (
                "在 free(buf) 后立即将 buf 置为 NULL，并在 memcpy 前校验 buf != NULL。"
                "推荐改用 OpenSSL 1.0.1g+ 版本，该版本已修复此问题。[MOCK DATA]"
            ),
        },
        {
            "vuln_type": "Heap_Overflow",
            "file_path": "src/crypto/mem.c",
            "line_number": 89,
            "code_context": (
                "87: char *dst = malloc(n);\n"
                "88: // n 由外部可控\n"
                "89: memcpy(dst, src, n + extra_bytes);  /* ← 越界写 */\n"
                "90: return dst;\n"
            ),
            "trigger_cond": (
                "当攻击者控制 Heartbeat 扩展的 payload_length 字段，"
                "使其大于实际 payload，导致服务器返回超出边界的内存内容。[MOCK DATA]"
            ),
            "fix_advice": (
                "在 memcpy 前严格校验 n + extra_bytes <= malloc 分配的大小。"
                "使用 strncat/strlcpy 等安全字符串函数替代 memcpy。[MOCK DATA]"
            ),
        },
    ]
}


async def _call_agent_b(
    source_root: str,
    cpp_files: list[str],
    target_vulns: list[str] | None = None,
) -> dict:
    """
    调用 ML-B 同学的 Agent B HTTP 接口，获取源码漏洞语义审计结果。

    Args:
        source_root:   解压后的源码根目录（绝对路径）
        cpp_files:     C/C++ 文件路径列表（相对于 source_root）
        target_vulns:  目标漏洞类型列表，如 ["UAF", "heap_overflow"]

    Returns:
        Agent B 返回的原始 JSON 字典
    """
    if settings.ML_MOCK_MODE:
        logger.info("[LLM] ML_MOCK_MODE=true，跳过真实 Agent B 调用，返回 Demo 数据")
        await asyncio.sleep(2)  # 模拟 LLM 响应延迟
        return _MOCK_AGENT_B_RESPONSE

    request_body = {
        "source_root":   source_root,
        "cpp_files":     cpp_files,
        "target_vulns":  target_vulns or [],   # 前端选择的目标漏洞类型
        "generate_harness": True,
    }

    logger.info(f"[LLM] 调用 Agent B 接口: {settings.ML_AGENT_B_URL}")
    try:
        async with httpx.AsyncClient(timeout=900.0) as client:  # LLM 调用最多等 15 分钟（七 Agent 链路较长）
            resp = await client.post(settings.ML_AGENT_B_URL, json=request_body)
            resp.raise_for_status()
            data = resp.json()
            logger.info(f"[LLM] Agent B 响应成功，HTTP {resp.status_code}")
            return data
    except httpx.TimeoutException:
        logger.error("[LLM] Agent B 调用超时（900s）")
        raise
    except httpx.HTTPStatusError as e:
        logger.error(f"[LLM] Agent B 返回错误 {e.response.status_code}: {e.response.text[:500]}")
        raise
    except Exception as e:
        logger.error(f"[LLM] Agent B 调用失败: {e}", exc_info=True)
        raise


async def _save_vulnerabilities(task_db_id: str, vulns: list[dict]) -> list[str]:
    """
    将 Agent B 返回的漏洞列表批量写入 vulnerability 表。

    Returns:
        写入的漏洞记录 UUID 字符串列表（供后续 Fuzzing 阶段使用）
    """
    if not vulns:
        logger.info(f"[LLM] task={task_db_id} Agent B 未发现漏洞")
        return []

    vuln_ids = []
    async with AsyncSessionLocal() as session:
        records = []
        for v in vulns:
            record = Vulnerability(
                task_id=uuid.UUID(task_db_id),
                vuln_type=v.get("vuln_type", "Unknown"),
                file_path=v.get("file_path"),
                line_number=v.get("line_number"),
                code_context=v.get("code_context"),
                trigger_cond=v.get("trigger_cond"),
                fix_advice=v.get("fix_advice"),
                verify_status=VerifyStatus.UNVERIFIED,
            )
            records.append(record)

        session.add_all(records)
        await session.flush()   # flush 后才能拿到数据库生成的 UUID
        vuln_ids = [str(r.id) for r in records]
        await session.commit()
        logger.info(f"[LLM] task={task_db_id} 写入 {len(records)} 条漏洞记录")

    return vuln_ids


@broker.task(
    task_name="llm_audit",
    max_retries=1,        # LLM 调用失败最多重试 1 次（防止过度消耗 token）
    retry_on_error=True,
)
async def run_llm_audit(
    task_db_id: str,
    source_path: str,
    is_dynamic: bool = False,
    target_vulns_json: str = "",
) -> dict:
    """
    LLM Multi-Agent 静态审计任务（阶段二）。

    执行步骤：
      1. 扫描 source_path 目录，获取 C/C++ 文件列表
      2. 调用 Agent B 接口进行语义漏洞审计
      3. 批量写入 vulnerability 表
      4. 根据 is_dynamic 决定：触发 Fuzzing 阶段 or 直接 Finalize

    Args:
        task_db_id:        PostgreSQL task.id
        source_path:       解压后的源码根目录
        is_dynamic:        是否触发 Fuzzing 阶段
        target_vulns_json: task.target_vulns 字段（JSON 字符串），如 '["UAF","heap_overflow"]'

    Returns:
        dict: {"vulns_found": int, "vuln_ids": list[str]}
    """
    import json

    logger.info(f"[LLM] 开始审计 task={task_db_id}, source={source_path}")

    # 兼容相对路径（与 sbom_task 保持一致）
    if not Path(source_path).is_absolute():
        source_path = str(Path(source_path).resolve())
        logger.info(f"[LLM] 相对路径已转换为绝对路径: {source_path}")

    # 如果收到的还是 zip 路径（直接提交到 llm 阶段时），先解压
    if source_path.endswith(".zip") and Path(source_path).is_file():
        from app.services.source_parser import parse_zip_source
        logger.info(f"[LLM] 检测到 ZIP，解压中: {source_path}")
        ctx = await asyncio.to_thread(parse_zip_source, source_path)
        source_path = ctx.source_root
        logger.info(f"[LLM] 解压完成，source_root: {source_path}")

    # ── 步骤 1: 枚举 C/C++ 文件列表（给 Agent B 使用）───────────────────────
    cpp_extensions = {".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".hh"}
    cpp_files: list[str] = []

    source_root = Path(source_path)
    if source_root.is_dir():
        for f in source_root.rglob("*"):
            if f.is_file() and f.suffix.lower() in cpp_extensions:
                rel = str(f.relative_to(source_root))
                cpp_files.append(rel)
        logger.info(f"[LLM] task={task_db_id} 枚举到 {len(cpp_files)} 个 C/C++ 文件")
    else:
        logger.warning(f"[LLM] source_path 不是目录: {source_path}，跳过文件枚举")

    # 解析前端传入的目标漏洞类型（JSON 字符串 → list）
    target_vulns: list[str] = []
    if target_vulns_json:
        try:
            parsed = json.loads(target_vulns_json)
            if isinstance(parsed, list):
                target_vulns = [str(v) for v in parsed]
        except Exception:
            logger.warning(f"[LLM] target_vulns_json 解析失败: {target_vulns_json!r}")

    logger.info(f"[LLM] task={task_db_id} 目标漏洞类型: {target_vulns or '全部'}")

    # ── 步骤 2: 调用 Agent B ─────────────────────────────────────────────────
    agent_b_result = await _call_agent_b(source_path, cpp_files, target_vulns)
    vulns = agent_b_result.get("vulnerabilities", [])

    # ── 步骤 3: 写入数据库 ───────────────────────────────────────────────────
    vuln_ids = await _save_vulnerabilities(task_db_id, vulns)

    result = {
        "vulns_found": len(vuln_ids),
        "vuln_ids": vuln_ids,
    }
    logger.info(f"[LLM] task={task_db_id} 审计完成: {result}")

    # ── 步骤 4: 链式触发下一阶段 ─────────────────────────────────────────────
    if is_dynamic:
        from app.worker.pipeline import trigger_fuzzing_stage
        await trigger_fuzzing_stage(task_db_id=task_db_id, source_path=source_path)
    else:
        from app.worker.pipeline import finalize_task_no_fuzzing
        await finalize_task_no_fuzzing.kiq(task_db_id)

    return result
