"""
SENTINEL 审计 Pipeline（链式触发模式）
──────────────────────────────────────────────────────────────────
TaskIQ 0.12.x 没有内置 Pipeline 类。

改用「任务内部触发下一阶段」的链式回调模式：
  SBOM 任务完成 → sbom_task 内部 kiq() 触发 LLM 任务
  LLM 任务完成  → llm_task 内部 kiq() 触发 Fuzzing 任务（或 Finalize）

这样设计比 Pipeline 更透明，且不依赖特定 Broker 对 Pipeline 的支持。

对外暴露的入口函数：
    await dispatch_audit_pipeline(task_db_id, source_path, is_dynamic)
"""
import logging
import uuid
from datetime import datetime, timezone

from app.core.broker import broker
from app.core.database import AsyncSessionLocal
from app.core.ws_manager import ws_manager
from app.models.task import Task, TaskStatus

logger = logging.getLogger(__name__)


async def _is_task_cancelled(task_db_id: str) -> bool:
    """
    检查任务是否已被用户取消（处于 FAILED 终态）。
    供链式触发函数在投递下一阶段前调用，实现协作式取消：
    一旦任务被 cancel 接口标记为 FAILED，后续阶段不再下发。
    """
    from sqlalchemy import select

    try:
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(Task.status).where(Task.id == uuid.UUID(task_db_id))
            )
            status = result.scalar_one_or_none()
            return status in (TaskStatus.FAILED, TaskStatus.COMPLETED)
    except Exception as e:
        logger.warning(f"[Pipeline] 取消状态检查失败 task={task_db_id}: {e}")
        return False


async def dispatch_audit_pipeline(
    task_db_id: str,
    source_path: str,
    is_dynamic: bool = False,
) -> None:
    """
    启动审计 Pipeline 的入口函数。

    只负责：
    1. 广播"排队中"状态
    2. 投递第一个阶段（SBOM）任务

    后续阶段由每个任务函数在执行完毕后自行触发（链式回调模式）。

    Args:
        task_db_id: PostgreSQL task.id 的字符串形式
        source_path: 源码文件路径或 GitHub 仓库地址
        is_dynamic: 是否开启 eBPF 动态验证（传递到链尾）
    """
    logger.info(
        f"[Pipeline] 下发审计 Pipeline: task={task_db_id}, is_dynamic={is_dynamic}"
    )

    # ── 广播：任务进入队列 ────────────────────────────────────────────────────
    await ws_manager.broadcast(
        task_db_id,
        {
            "stage":      "pending",
            "percent":    5,
            "message":    "✅ 审计任务已提交，正在进入任务队列...",
            "log_stream": "",
        },
    )

    # ── 投递第一阶段（SBOM 分析）──────────────────────────────────────────────
    # is_dynamic 通过 labels 透传，后续阶段在 llm_task 完成后读取，决定是否触发 Fuzzing
    from app.worker.sbom_task import run_sbom_analysis
    await (
        run_sbom_analysis
        .kicker()
        .with_labels(task_db_id=task_db_id, stage="sbom", is_dynamic=str(is_dynamic))
        .kiq(task_db_id, source_path, is_dynamic)
    )

    logger.info(f"[Pipeline] task={task_db_id} 第一阶段（SBOM）已投递，等待 Worker 拾取")


# ── 阶段二触发函数（由 sbom_task 在成功时调用）────────────────────────────────
async def trigger_llm_stage(task_db_id: str, source_path: str, is_dynamic: bool) -> None:
    """sbom_task 执行成功后调用此函数，投递 LLM 审计任务"""
    if await _is_task_cancelled(task_db_id):
        logger.info(f"[Pipeline] task={task_db_id} 已取消，跳过 LLM 阶段投递")
        return
    from app.worker.llm_task import run_llm_audit
    await (
        run_llm_audit
        .kicker()
        .with_labels(task_db_id=task_db_id, stage="llm")
        .kiq(task_db_id, source_path, is_dynamic)   # is_dynamic 作为位置参数传入
    )
    logger.info(f"[Pipeline] task={task_db_id} 第二阶段（LLM）已投递")


# ── 阶段三触发函数（由 llm_task 在成功时调用）────────────────────────────────
async def trigger_fuzzing_stage(task_db_id: str, source_path: str) -> None:
    """llm_task 执行成功且 is_dynamic=True 时调用，投递 Fuzzing 任务"""
    if await _is_task_cancelled(task_db_id):
        logger.info(f"[Pipeline] task={task_db_id} 已取消，跳过 Fuzzing 阶段投递")
        return
    from app.worker.fuzzing_task import run_dynamic_fuzzing
    await (
        run_dynamic_fuzzing
        .kicker()
        .with_labels(task_db_id=task_db_id, stage="fuzzing")
        .kiq(task_db_id, source_path)
    )
    logger.info(f"[Pipeline] task={task_db_id} 第三阶段（Fuzzing）已投递")


# ── 非动态模式收尾函数（由 llm_task 在 is_dynamic=False 时调用）──────────────
@broker.task(task_name="finalize_no_fuzzing")
async def finalize_task_no_fuzzing(task_db_id: str) -> None:
    """
    非动态模式的收尾任务（LLM 审计完成后异步调用）。
    将 Task 状态更新为 COMPLETED，并广播最终完成消息。
    """
    from sqlalchemy import select

    logger.info(f"[Finalize] 收尾任务开始 task={task_db_id}")
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(Task).where(Task.id == uuid.UUID(task_db_id))
        )
        task = result.scalar_one_or_none()
        if task and task.status not in (TaskStatus.FAILED, TaskStatus.COMPLETED):
            task.status = TaskStatus.COMPLETED
            task.completed_at = datetime.now(timezone.utc)
            await session.commit()
            logger.info(f"[Finalize] task={task_db_id} 已标记为 COMPLETED（静态审计模式）")

    await ws_manager.broadcast(
        task_db_id,
        {
            "stage":      "done",
            "percent":    100,
            "message":    "🎉 静态代码审计完成！报告已生成，请前往报告页查看。",
            "log_stream": "",
        },
    )
