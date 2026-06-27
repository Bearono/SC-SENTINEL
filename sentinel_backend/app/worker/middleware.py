import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from taskiq import TaskiqMessage, TaskiqMiddleware, TaskiqResult

from app.core.database import AsyncSessionLocal
from app.core.ws_manager import ws_manager
from app.models.task import TaskStatus

logger = logging.getLogger(__name__)

_STAGE_PERCENT: dict[str, int] = {
    "sbom": 20,
    "llm": 60,
    "fuzzing": 90,
    "done": 100,
}

_STAGE_TO_STATUS: dict[str, TaskStatus] = {
    "sbom": TaskStatus.ANALYZING_DEPS,
    "llm": TaskStatus.LLM_AUDITING,
    "fuzzing": TaskStatus.FUZZING,
}

_STAGE_START_MESSAGES: dict[str, tuple[str, str]] = {
    "sbom": (
        "Dependency and SBOM analysis started.",
        "[SBOM] Parsing project files and dependency metadata...\n",
    ),
    "llm": (
        "Static vulnerability audit started.",
        "[LLM] Starting multi-agent static audit...\n",
    ),
    "fuzzing": (
        "Dynamic AFL++ and eBPF verification started.",
        "[FUZZING] Preparing harness packages and sandbox runtime...\n",
    ),
}


async def _update_task_db(
    task_db_id: str,
    new_status: TaskStatus,
    error_message: str | None = None,
    mark_complete: bool = False,
) -> bool:
    from sqlalchemy import select
    from app.models.task import Task

    try:
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(Task).where(Task.id == uuid.UUID(task_db_id))
            )
            task = result.scalar_one_or_none()
            if task is None:
                logger.warning("[Middleware] task=%s not found", task_db_id)
                return False

            if task.status in (TaskStatus.FAILED, TaskStatus.COMPLETED) and not mark_complete:
                logger.info("[Middleware] task=%s already terminal status=%s", task_db_id, task.status.value)
                return False

            task.status = new_status
            if error_message is not None:
                task.error_message = error_message
            if mark_complete:
                task.completed_at = datetime.now(timezone.utc)

            await session.commit()
            logger.info("[Middleware] task=%s status=%s", task_db_id, new_status.value)
            return True
    except Exception as exc:
        logger.error("[Middleware] failed to update task=%s: %s", task_db_id, exc, exc_info=True)
        return False


async def _broadcast_progress(
    task_db_id: str,
    stage: str,
    percent: int,
    message: str,
    log_stream: str = "",
) -> None:
    await ws_manager.broadcast(
        task_db_id,
        {
            "stage": stage,
            "percent": percent,
            "message": message,
            "log_stream": log_stream,
        },
    )


class SentinelMiddleware(TaskiqMiddleware):
    async def pre_execute(self, message: TaskiqMessage) -> TaskiqMessage:
        task_db_id: str = message.labels.get("task_db_id", "")
        stage: str = message.labels.get("stage", "unknown")
        if not task_db_id:
            return message

        new_status = _STAGE_TO_STATUS.get(stage, TaskStatus.PENDING)
        percent = _STAGE_PERCENT.get(stage, 0)
        updated = await _update_task_db(task_db_id, new_status)
        if not updated:
            await _broadcast_progress(
                task_db_id,
                stage="failed",
                percent=percent,
                message="Task was cancelled or already finished; pipeline stopped.",
                log_stream=f"[{stage.upper()}] skipped because task is terminal.\n",
            )
            return message

        human_msg, stream_msg = _STAGE_START_MESSAGES.get(
            stage,
            (f"Task stage {stage} started.", f"[{stage.upper()}] started.\n"),
        )
        await _broadcast_progress(task_db_id, stage, percent, human_msg, stream_msg)
        return message

    async def post_execute(
        self,
        message: TaskiqMessage,
        result: TaskiqResult[Any],
    ) -> None:
        task_db_id: str = message.labels.get("task_db_id", "")
        stage: str = message.labels.get("stage", "unknown")
        if not task_db_id:
            return

        percent = _STAGE_PERCENT.get(stage, 50)
        if result.is_err:
            err_str = str(result.error)[:1000]
            logger.error("[Middleware] task=%s stage=%s failed: %s", task_db_id, stage, err_str)
            await _update_task_db(
                task_db_id,
                TaskStatus.FAILED,
                error_message=f"[{stage}] {err_str}",
                mark_complete=True,
            )
            await _broadcast_progress(
                task_db_id,
                stage="failed",
                percent=percent,
                message=f"Stage [{stage}] failed. Check backend logs for details.",
                log_stream=f"[{stage.upper()}] ERROR: {err_str}\n",
            )
            return

        logger.info("[Middleware] task=%s stage=%s succeeded", task_db_id, stage)
        await _broadcast_progress(
            task_db_id,
            stage=stage,
            percent=percent,
            message=f"Stage [{stage}] completed.",
            log_stream=f"[{stage.upper()}] completed successfully.\n",
        )
