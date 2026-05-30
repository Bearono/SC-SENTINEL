"""
TaskIQ Middleware：SENTINEL 任务生命周期拦截器
──────────────────────────────────────────────
拦截点：
  pre_execute   → 任务开始执行前（状态更新为 running）
  post_execute  → 任务执行完成后（状态更新为 success / failed）

每次状态变更时：
  1. 写入 PostgreSQL task 表（状态 + error_message + completed_at）
  2. 通过 ws_manager 向前端 WebSocket 广播实时进度

重要约束：
  Middleware 在 Worker 进程中运行（不在 FastAPI 进程中），
  因此需要自己创建独立的数据库 Session，不能依赖 FastAPI 的 get_db。
"""
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from taskiq import TaskiqMessage, TaskiqMiddleware, TaskiqResult

from app.core.database import AsyncSessionLocal
from app.core.ws_manager import ws_manager
from app.models.task import TaskStatus

logger = logging.getLogger(__name__)

# ── 阶段到进度百分比的映射（供前端进度条使用）──────────────────────────────────
_STAGE_PERCENT: dict[str, int] = {
    "sbom":    20,   # SBOM / 依赖分析
    "llm":     60,   # LLM Multi-Agent 静态审计
    "fuzzing": 90,   # AFL++ + eBPF 动态验证
    "done":   100,   # 全部完成
}

# ── stage 名称 → TaskStatus 枚举的映射 ─────────────────────────────────────────
_STAGE_TO_STATUS: dict[str, TaskStatus] = {
    "sbom":    TaskStatus.ANALYZING_DEPS,
    "llm":     TaskStatus.LLM_AUDITING,
    "fuzzing": TaskStatus.FUZZING,
}


async def _update_task_db(
    task_db_id: str,
    new_status: TaskStatus,
    error_message: str | None = None,
    mark_complete: bool = False,
) -> None:
    """
    内部辅助：在独立 Session 里更新 task 表的状态字段。
    Worker 进程没有 FastAPI 的请求上下文，必须手动管理 Session 生命周期。
    """
    from sqlalchemy import select
    from app.models.task import Task

    try:
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(Task).where(Task.id == uuid.UUID(task_db_id))
            )
            task = result.scalar_one_or_none()
            if task is None:
                logger.warning(f"[Middleware] task_db_id={task_db_id} 不存在，跳过状态更新")
                return

            task.status = new_status
            if error_message is not None:
                task.error_message = error_message
            if mark_complete:
                task.completed_at = datetime.now(timezone.utc)

            await session.commit()
            logger.info(f"[Middleware] task={task_db_id} 状态更新为 {new_status.value}")
    except Exception as e:
        logger.error(f"[Middleware] 数据库更新失败 task={task_db_id}: {e}", exc_info=True)


async def _broadcast_progress(
    task_db_id: str,
    stage: str,
    percent: int,
    message: str,
    log_stream: str = "",
) -> None:
    """内部辅助：向指定 task 的所有 WebSocket 连接广播进度消息"""
    await ws_manager.broadcast(
        task_db_id,
        {
            "stage":      stage,
            "percent":    percent,
            "message":    message,
            "log_stream": log_stream,
        },
    )


class SentinelMiddleware(TaskiqMiddleware):
    """
    SENTINEL 任务生命周期中间件。

    TaskiqMessage.labels 中必须携带以下字段（由各 Task 函数在 kicker 时注入）：
      - task_db_id : str  → PostgreSQL task.id（UUID 字符串）
      - stage      : str  → "sbom" | "llm" | "fuzzing"
    """

    async def pre_execute(
        self,
        message: TaskiqMessage,
    ) -> TaskiqMessage:
        """任务即将执行：更新 DB 状态为 running，广播"开始"消息"""
        task_db_id: str = message.labels.get("task_db_id", "")
        stage: str = message.labels.get("stage", "unknown")

        if not task_db_id:
            return message  # 非审计任务（如测试任务），跳过

        new_status = _STAGE_TO_STATUS.get(stage, TaskStatus.PENDING)
        percent = _STAGE_PERCENT.get(stage, 0)

        stage_labels = {
            "sbom":    "【阶段 1/3】正在解析 SBOM 依赖树，扫描已知 CVE 漏洞库...",
            "llm":     "【阶段 2/3】LLM Multi-Agent 正在进行静态代码审计...",
            "fuzzing": "【阶段 3/3】AFL++ + eBPF 沙箱动态验证启动中...",
        }
        human_msg = stage_labels.get(stage, f"任务阶段 {stage} 开始执行")

        await _update_task_db(task_db_id, new_status)
        await _broadcast_progress(task_db_id, stage, percent, human_msg)
        return message

    async def post_execute(
        self,
        message: TaskiqMessage,
        result: TaskiqResult[Any],
    ) -> None:
        """任务执行完毕：根据是否异常更新 DB 状态，广播"完成"或"失败"消息"""
        task_db_id: str = message.labels.get("task_db_id", "")
        stage: str = message.labels.get("stage", "unknown")

        if not task_db_id:
            return

        if result.is_err:
            # 任务抛异常：写入失败状态
            err_str = str(result.error)[:1000]  # 截断，防止超长日志
            logger.error(f"[Middleware] task={task_db_id} stage={stage} 执行失败: {err_str}")
            await _update_task_db(
                task_db_id,
                TaskStatus.FAILED,
                error_message=f"[{stage}] {err_str}",
                mark_complete=True,
            )
            await _broadcast_progress(
                task_db_id,
                stage="failed",
                percent=_STAGE_PERCENT.get(stage, 0),
                message=f"❌ 阶段 [{stage}] 执行失败，请查看错误日志",
                log_stream=err_str,
            )
        else:
            # 仅在最后一个阶段（fuzzing / llm 非动态）才将状态改为 completed
            # 单阶段完成仅广播进度，由 pipeline 串联完成后最终收尾
            done_percent = _STAGE_PERCENT.get(stage, 50)
            logger.info(f"[Middleware] task={task_db_id} stage={stage} 执行成功")
            await _broadcast_progress(
                task_db_id,
                stage=stage,
                percent=done_percent,
                message=f"✅ 阶段 [{stage}] 执行完成",
            )
