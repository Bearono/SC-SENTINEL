"""
7 个核心 HTTP 接口实现
POST   /api/v1/tasks                          → 提交审计任务与源码上传
GET    /api/v1/tasks                          → 查询历史任务列表（分页）
GET    /api/v1/tasks/{task_id}                → 单体状态查询（轻量级降级轮询）
GET    /api/v1/tasks/{task_id}/report         → 获取终极审计报告（四表联查）
POST   /api/v1/tasks/{task_id}/cancel         → 强制终止任务
GET    /api/v1/tasks/{task_id}/export-pdf     → 导出 PDF 审计报告（文件流下载）
"""
import os
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, File, Form, Query, UploadFile
from fastapi.responses import Response, StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.database import get_db
from app.core.pdf_generator import generate_audit_pdf
from app.models.task import SourceType, Task, TaskStatus
from app.models.vulnerability import Vulnerability
from app.schemas.common import fail, ok
from app.schemas.task import (
    ComponentOut,
    EbpfLogOut,
    ReportOut,
    ReportSummary,
    TaskCreateOut,
    TaskListItem,
    TaskStatusOut,
    VulnerabilityOut,
)

router = APIRouter(prefix="/tasks", tags=["Tasks"])

# ── 文件上传目录（项目根目录下的 uploads/）─────────────────────────────────────
UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)


# ════════════════════════════════════════════════════════════════════════════
# API 1: POST /api/v1/tasks — 提交审计任务与源码上传
# ════════════════════════════════════════════════════════════════════════════
@router.post(
    "",
    summary="提交审计任务",
    description="接收 ZIP 文件或 GitHub 仓库地址，创建一条新的审计任务记录，初始状态为 pending。",
)
async def create_task(
    project_name: str = Form(..., description="项目名称，如 Heartbleed-test"),
    source_type: str = Form(..., description="源码来源，只能为 'zip' 或 'github'"),
    source_path: Optional[str] = Form(None, description="GitHub 仓库 URL（source_type 为 github 时必填）"),
    file: Optional[UploadFile] = File(None, description="ZIP 源码包（source_type 为 zip 时必填）"),
    target_vulns: Optional[str] = Form(None, description="目标漏洞类型，JSON 字符串，如 '[\"UAF\",\"Heap_Overflow\"]'"),
    is_dynamic: Optional[str] = Form("false", description="是否开启 eBPF 动态验证，传 'true' 或 'false'"),
    db: AsyncSession = Depends(get_db),
):
    # ── 校验 source_type ──────────────────────────────────────────────────
    try:
        src_type = SourceType(source_type.lower())
    except ValueError:
        return fail(400, f"source_type 必须为 'zip' 或 'github'，收到: '{source_type}'")

    # ── 条件必填校验 & 文件存储 ───────────────────────────────────────────
    task_id = uuid.uuid4()

    if src_type == SourceType.ZIP:
        if not file:
            return fail(400, "source_type 为 zip 时，file 为必传字段")

        # 为每个任务创建独立子目录，防止同名文件互相覆盖
        save_dir = UPLOAD_DIR / str(task_id)
        save_dir.mkdir(parents=True, exist_ok=True)
        safe_filename = Path(file.filename).name  # 去掉路径中的目录穿越风险
        file_path = save_dir / safe_filename

        with open(file_path, "wb") as f:
            shutil.copyfileobj(file.file, f)

        stored_path = str(file_path)

    else:  # SourceType.GITHUB
        if not source_path:
            return fail(400, "source_type 为 github 时，source_path（仓库 URL）为必传字段")
        stored_path = source_path

    # ── 解析布尔字符串 ────────────────────────────────────────────────────
    is_dynamic_bool = isinstance(is_dynamic, str) and is_dynamic.lower() == "true"

    # ── 写入数据库 ────────────────────────────────────────────────────────
    task = Task(
        id=task_id,
        project_name=project_name,
        source_type=src_type,
        source_path=stored_path,
        status=TaskStatus.PENDING,
        target_vulns=target_vulns,
        is_dynamic=is_dynamic_bool,
    )
    db.add(task)
    await db.flush()  # flush 使 task 对象获得数据库写入后的完整状态

    return ok(
        TaskCreateOut.model_validate(task).model_dump(mode="json"),
        "审计任务创建成功，等待调度执行",
    )


# ════════════════════════════════════════════════════════════════════════════
# API 2: GET /api/v1/tasks — 查询历史任务列表（分页）
# ════════════════════════════════════════════════════════════════════════════
@router.get(
    "",
    summary="查询历史任务列表",
    description="按创建时间倒序返回分页的审计任务列表。",
)
async def list_tasks(
    page: int = Query(1, ge=1, description="页码，从 1 开始"),
    size: int = Query(10, ge=1, le=100, description="每页条数，最大 100"),
    db: AsyncSession = Depends(get_db),
):
    offset = (page - 1) * size

    # 查总数
    total_result = await db.execute(select(func.count()).select_from(Task))
    total = total_result.scalar_one()

    # 查分页数据（按创建时间倒序）
    result = await db.execute(
        select(Task).order_by(Task.created_at.desc()).offset(offset).limit(size)
    )
    tasks = result.scalars().all()

    items = [
        TaskListItem.model_validate(t).model_dump(mode="json") for t in tasks
    ]

    return ok({"total": total, "items": items})


# ════════════════════════════════════════════════════════════════════════════
# API 3: GET /api/v1/tasks/{task_id} — 单体状态查询（降级轮询）
# ════════════════════════════════════════════════════════════════════════════
@router.get(
    "/{task_id}",
    summary="查询任务状态",
    description="极轻量级的单表查询，仅返回 id + status + created_at。"
                "供前端在 WebSocket 断开时每 3 秒静默轮询当前阶段。",
)
async def get_task_status(
    task_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Task).where(Task.id == task_id))
    task = result.scalar_one_or_none()

    if not task:
        return fail(404, f"任务 {task_id} 不存在")

    return ok(TaskStatusOut.model_validate(task).model_dump(mode="json"))


# ════════════════════════════════════════════════════════════════════════════
# API 4: GET /api/v1/tasks/{task_id}/report — 终极审计报告（四表联查）
# ════════════════════════════════════════════════════════════════════════════
@router.get(
    "/{task_id}/report",
    summary="获取终极审计报告",
    description="状态变为 completed 后调用。后端一次性聚合 task + component_risk + "
                "vulnerability + ebpf_event_log 四张表，计算总耗时并返回完整报告。",
)
async def get_task_report(
    task_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    # 四表联查：使用 selectinload 预加载所有关联关系，避免 N+1 查询
    result = await db.execute(
        select(Task)
        .where(Task.id == task_id)
        .options(
            selectinload(Task.component_risks),
            selectinload(Task.vulnerabilities).selectinload(Vulnerability.ebpf_events),
        )
    )
    task = result.scalar_one_or_none()

    if not task:
        return fail(404, f"任务 {task_id} 不存在")

    if task.status != TaskStatus.COMPLETED:
        return fail(
            400,
            f"任务尚未完成，当前状态为 '{task.status.value}'，请等待任务执行完毕后再获取报告",
        )

    # ── 计算总耗时 ────────────────────────────────────────────────────────
    total_seconds: Optional[float] = None
    if task.completed_at and task.created_at:
        # 确保两个时间都有时区信息，然后相减
        ca = task.created_at
        co = task.completed_at
        if ca.tzinfo is None:
            ca = ca.replace(tzinfo=timezone.utc)
        if co.tzinfo is None:
            co = co.replace(tzinfo=timezone.utc)
        total_seconds = (co - ca).total_seconds()

    # ── 构建四层嵌套响应 ──────────────────────────────────────────────────
    summary = ReportSummary(
        project_name=task.project_name,
        total_time_seconds=total_seconds,
        is_dynamic=task.is_dynamic,
    )

    components = [ComponentOut.model_validate(c) for c in task.component_risks]

    vulnerabilities = []
    for v in task.vulnerabilities:
        ebpf_logs = [EbpfLogOut.model_validate(e) for e in v.ebpf_events]
        vuln_out = VulnerabilityOut(
            id=v.id,
            vuln_type=v.vuln_type,
            file_path=v.file_path,
            line_number=v.line_number,
            code_context=v.code_context,
            verify_status=v.verify_status,
            ebpf_logs=ebpf_logs,
        )
        vulnerabilities.append(vuln_out)

    report = ReportOut(
        summary=summary,
        components=components,
        vulnerabilities=vulnerabilities,
    )

    return ok(report.model_dump(mode="json"))


# ════════════════════════════════════════════════════════════════════════════
# API 5: POST /api/v1/tasks/{task_id}/cancel — 强制终止任务
# ════════════════════════════════════════════════════════════════════════════
@router.post(
    "/{task_id}/cancel",
    summary="强制终止任务",
    description="紧急制动阀。将任务状态改为 failed，记录取消原因。"
                "后续阶段接入 Docker SDK 后，此处将同步 kill Fuzzing 沙箱容器。",
)
async def cancel_task(
    task_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Task).where(Task.id == task_id))
    task = result.scalar_one_or_none()

    if not task:
        return fail(404, f"任务 {task_id} 不存在")

    # 已终结的任务不可再次取消
    if task.status in (TaskStatus.COMPLETED, TaskStatus.FAILED):
        return fail(
            400,
            f"任务已处于终态（当前状态: '{task.status.value}'），无需取消",
        )

    # ── TODO: 第三阶段接入 Docker SDK 后，在此处 kill Fuzzing 容器 ────────
    # container_name = f"sentinel_fuzzer_{task_id}"
    # docker_client.containers.get(container_name).stop()

    # -- 更新数据库状态 ────────────────────────────────────────────────────
    task.status = TaskStatus.FAILED
    task.error_message = "用户手动取消任务"
    task.completed_at = datetime.now(timezone.utc)

    return ok(None, f"任务 {task_id} 已强制终止")


# ════════════════════════════════════════════════════════════════════════════
# API 7: GET /api/v1/tasks/{task_id}/export-pdf — 导出 PDF 审计报告
# 执行手册出处：
#   ML 同学 B 任务分配 → "PDF 报告导出：使用 WeasyPrint 或 ReportLab 生成可下载的 PDF 审计报告"
#   页面三顶部概览卡片 → "下载 PDF 按钮"
# ════════════════════════════════════════════════════════════════════════════
@router.get(
    "/{task_id}/export-pdf",
    summary="导出 PDF 审计报告",
    description=(
        "前端点击【下载 PDF】按钮时调用。后端调用 ReportLab 生成完整的 PDF 审计报告，"
        "以文件流形式返回（Content-Type: application/pdf），浏览器会自动触发文件下载。"
        "任务必须处于 completed 状态才可导出。"
    ),
    response_class=Response,
)
async def export_task_pdf(
    task_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    # -- 四表联查（与 report 接口保持一致，预加载所有关联数据） ───────────────
    result = await db.execute(
        select(Task)
        .where(Task.id == task_id)
        .options(
            selectinload(Task.component_risks),
            selectinload(Task.vulnerabilities).selectinload(Vulnerability.ebpf_events),
        )
    )
    task = result.scalar_one_or_none()

    if not task:
        return fail(404, f"任务 {task_id} 不存在")

    if task.status != TaskStatus.COMPLETED:
        return fail(
            400,
            f"任务尚未完成（当前状态: '{task.status.value}'），只有 completed 状态才可导出 PDF",
        )

    # -- 调用 ReportLab 生成 PDF 字节流 ──────────────────────────────────────
    pdf_bytes = generate_audit_pdf(task)

    # -- 生成安全文件名（项目名去除非 ASCII，避免浏览器下载时 Content-Disposition 乱码）
    safe_name = (
        task.project_name.encode("ascii", "ignore").decode("ascii").replace(" ", "_")
        or str(task_id)
    )
    filename = f"SENTINEL_Report_{safe_name}_{str(task_id)[:8]}.pdf"

    # -- 以 StreamingResponse 返回，触发浏览器下载 ────────────────────────────
    return StreamingResponse(
        iter([pdf_bytes]),
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Content-Length": str(len(pdf_bytes)),
        },
    )
