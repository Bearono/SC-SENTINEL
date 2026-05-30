"""
阶段一任务：SBOM 依赖分析（调用 ML-A 同学的 Agent A 接口）
──────────────────────────────────────────────────────────────────────
后端职责（执行手册第 3 章）：
  1. 解压 ZIP 源码包，提取依赖声明文件（CMakeLists.txt / Makefile 等）
  2. 将解析后的依赖信息 POST 给 ML-A 的 Agent A 接口
  3. 接收 Agent A 返回的 CVE 风险列表，批量写入 component_risk 表
  4. 完成后自动触发 LLM 阶段（链式回调）

Mock 模式（ML_MOCK_MODE=true 时）：
  跳过真实 HTTP 调用，返回 Heartbleed 演示数据，用于开发和演示。

接收 Agent A 返回格式（约定）：
  {
    "components": [
      {
        "library_name": "openssl",
        "version": "1.0.1e",
        "cve_id": "CVE-2014-0160",
        "cvss_score": 7.8,
        "severity": "high",           // critical/high/medium/low/unknown
        "description": "Heartbleed...",
        "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2014-0160"
      }
    ]
  }
"""
import asyncio
import logging
import uuid
from pathlib import Path

import httpx

from app.core.broker import broker
from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.models.component_risk import ComponentRisk, Severity

logger = logging.getLogger(__name__)

# ── Severity 字符串 → 枚举映射 ────────────────────────────────────────────────
_SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high":     Severity.HIGH,
    "medium":   Severity.MEDIUM,
    "low":      Severity.LOW,
    "unknown":  Severity.UNKNOWN,
}

# ── Mock 演示数据（ML_MOCK_MODE=true 时使用）─────────────────────────────────
_MOCK_AGENT_A_RESPONSE = {
    "components": [
        {
            "library_name": "openssl",
            "version": "1.0.1e",
            "cve_id": "CVE-2014-0160",
            "cvss_score": 7.8,
            "severity": "high",
            "description": (
                "Heartbleed: The TLS heartbeat extension reads up to 64KB of memory "
                "beyond the end of a buffer. Remote attackers can exploit this to "
                "expose sensitive data including private keys. [MOCK DATA]"
            ),
            "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2014-0160",
        },
        {
            "library_name": "libpng",
            "version": "1.6.34",
            "cve_id": "CVE-2018-14048",
            "cvss_score": 6.5,
            "severity": "medium",
            "description": (
                "An out of bounds read in contrib/tools/pngfix.c can cause a crash "
                "when processing a PNG file with a crafted chunk type. [MOCK DATA]"
            ),
            "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2018-14048",
        },
    ]
}


async def _call_agent_a(dep_files: list[dict], includes: list[str], cpp_files: list[str]) -> dict:
    """
    调用 ML-A 同学的 Agent A HTTP 接口，获取依赖 CVE 风险分析结果。

    Args:
        dep_files: 依赖声明文件内容列表（来自 source_parser）
        includes:  #include 引用列表（来自 source_parser）
        cpp_files: C/C++ 文件路径列表（供 Agent A 评估覆盖范围）

    Returns:
        Agent A 返回的原始 JSON 字典
    """
    if settings.ML_MOCK_MODE:
        logger.info("[SBOM] ML_MOCK_MODE=true，跳过真实 Agent A 调用，返回 Demo 数据")
        await asyncio.sleep(1)   # 模拟网络延迟，使进度条动画更自然
        return _MOCK_AGENT_A_RESPONSE

    request_body = {
        "dep_files": dep_files,
        "includes":  includes,
        "cpp_files": cpp_files,
    }

    logger.info(f"[SBOM] 调用 Agent A 接口: {settings.ML_AGENT_A_URL}")
    try:
        async with httpx.AsyncClient(timeout=120.0) as client:
            resp = await client.post(settings.ML_AGENT_A_URL, json=request_body)
            resp.raise_for_status()
            data = resp.json()
            logger.info(f"[SBOM] Agent A 响应成功，HTTP {resp.status_code}")
            return data
    except httpx.TimeoutException:
        logger.error("[SBOM] Agent A 调用超时（120s）")
        raise
    except httpx.HTTPStatusError as e:
        logger.error(f"[SBOM] Agent A 返回错误状态码 {e.response.status_code}: {e.response.text[:500]}")
        raise
    except Exception as e:
        logger.error(f"[SBOM] Agent A 调用失败: {e}", exc_info=True)
        raise


async def _save_component_risks(task_db_id: str, components: list[dict]) -> int:
    """
    将 Agent A 返回的组件风险列表批量写入 component_risk 表。

    Returns:
        写入的记录条数
    """
    if not components:
        logger.info(f"[SBOM] task={task_db_id} Agent A 未发现组件风险")
        return 0

    async with AsyncSessionLocal() as session:
        records = []
        for comp in components:
            severity_str = str(comp.get("severity", "unknown")).lower()
            severity = _SEVERITY_MAP.get(severity_str, Severity.UNKNOWN)

            record = ComponentRisk(
                task_id=uuid.UUID(task_db_id),
                library_name=comp.get("library_name", "unknown"),
                version=comp.get("version"),
                cve_id=comp.get("cve_id"),
                cvss_score=comp.get("cvss_score"),
                severity=severity,
                description=comp.get("description"),
                nvd_url=comp.get("nvd_url"),
            )
            records.append(record)

        session.add_all(records)
        await session.commit()
        logger.info(f"[SBOM] task={task_db_id} 写入 {len(records)} 条组件风险记录")
        return len(records)


@broker.task(
    task_name="sbom_analysis",
    max_retries=2,
    retry_on_error=True,
)
async def run_sbom_analysis(task_db_id: str, source_path: str, is_dynamic: bool = False) -> dict:
    """
    SBOM 依赖分析任务（阶段一）。

    执行步骤：
      1. 判断 source_path 是 ZIP 文件还是已解压目录
      2. 调用 source_parser 提取依赖信息
      3. 调用 Agent A 接口获取 CVE 风险列表
      4. 批量写入 component_risk 表
      5. 链式触发 LLM 审计阶段

    Labels（由 pipeline.dispatch_audit_pipeline 注入）：
      task_db_id : str  → PostgreSQL task.id
      stage      : "sbom"

    Returns:
        dict: {"components_found": int, "high_risk_count": int, "source_root": str}
    """
    logger.info(f"[SBOM] 开始分析 task={task_db_id}, source={source_path}")

    # ── 步骤 1: 解压 ZIP 或使用已解压目录 ────────────────────────────────────
    from app.services.source_parser import parse_zip_source, parse_source_context

    source_root = source_path
    ctx = None

    if source_path.endswith(".zip") and Path(source_path).is_file():
        # 用户上传了 ZIP 文件，解压并解析
        logger.info(f"[SBOM] 检测到 ZIP 文件，开始解压: {source_path}")
        ctx = await asyncio.to_thread(parse_zip_source, source_path)
        source_root = ctx.source_root
        logger.info(f"[SBOM] ZIP 解压完成，源码根目录: {source_root}")
    elif Path(source_path).is_dir():
        # 已经是目录（如 GitHub clone 后的路径）
        ctx = await asyncio.to_thread(parse_source_context, source_path)
        source_root = ctx.source_root
    else:
        # GitHub 仓库地址或其他非本地路径，暂不解析（交给 ML-A 处理）
        logger.warning(f"[SBOM] source_path 非本地文件/目录: {source_path}，跳过本地解析")

    # ── 步骤 2: 调用 Agent A 接口 ────────────────────────────────────────────
    dep_files = ctx.dep_files if ctx else []
    includes  = ctx.includes  if ctx else []
    cpp_files = ctx.cpp_files if ctx else []

    agent_a_result = await _call_agent_a(dep_files, includes, cpp_files)
    components = agent_a_result.get("components", [])

    # ── 步骤 3: 写入数据库 ───────────────────────────────────────────────────
    saved_count = await _save_component_risks(task_db_id, components)
    high_risk_count = sum(
        1 for c in components
        if c.get("severity", "").lower() in ("critical", "high")
    )

    result = {
        "components_found": saved_count,
        "high_risk_count": high_risk_count,
        "source_root": source_root,
    }
    logger.info(f"[SBOM] task={task_db_id} 分析完成: {result}")

    # ── 步骤 4: 链式触发 LLM 审计 ───────────────────────────────────────────
    from app.worker.pipeline import trigger_llm_stage
    await trigger_llm_stage(
        task_db_id=task_db_id,
        source_path=source_root,     # 传解压后的目录路径给 LLM 阶段
        is_dynamic=is_dynamic,
    )

    return result
