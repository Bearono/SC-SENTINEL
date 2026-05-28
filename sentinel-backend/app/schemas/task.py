"""
任务相关的所有 Pydantic 传输模型（Schemas / DTOs）
职责：定义接口的输入/输出格式，与前端约定数据边界。
与 ORM models 的区别：models 给数据库看，schemas 给前端和接口看。
"""
import uuid
from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel

from app.models.component_risk import Severity
from app.models.ebpf_event_log import EbpfEventType
from app.models.task import TaskStatus
from app.models.vulnerability import VerifyStatus


# ══════════════════════════════════════════════════════════════════════
# API 1: POST /api/v1/tasks 响应体
# ══════════════════════════════════════════════════════════════════════

class TaskCreateOut(BaseModel):
    """创建任务后返回给前端的基础信息"""
    id: uuid.UUID
    project_name: str
    status: TaskStatus
    created_at: datetime

    model_config = {"from_attributes": True}


# ══════════════════════════════════════════════════════════════════════
# API 2: GET /api/v1/tasks 分页列表
# ══════════════════════════════════════════════════════════════════════

class TaskListItem(BaseModel):
    """任务列表中的单条摘要"""
    id: uuid.UUID
    project_name: str
    status: TaskStatus
    created_at: datetime

    model_config = {"from_attributes": True}


class TaskListOut(BaseModel):
    """分页任务列表响应体"""
    total: int
    items: List[TaskListItem]


# ══════════════════════════════════════════════════════════════════════
# API 3: GET /api/v1/tasks/{task_id} 单体状态（轻量级轮询）
# ══════════════════════════════════════════════════════════════════════

class TaskStatusOut(BaseModel):
    """仅返回 id + status + created_at，供前端降级轮询使用"""
    id: uuid.UUID
    status: TaskStatus
    created_at: datetime

    model_config = {"from_attributes": True}


# ══════════════════════════════════════════════════════════════════════
# API 4: GET /api/v1/tasks/{task_id}/report 终极审计报告
# ══════════════════════════════════════════════════════════════════════

class ReportSummary(BaseModel):
    """报告概览：项目名 + 总耗时 + 是否动态验证"""
    project_name: str
    total_time_seconds: Optional[float] = None
    is_dynamic: bool


class ComponentOut(BaseModel):
    """组件风险条目（来自 component_risk 表）"""
    library_name: str
    version: Optional[str] = None
    cve_id: Optional[str] = None
    severity: Severity

    model_config = {"from_attributes": True}


class EbpfLogOut(BaseModel):
    """eBPF 内核事件条目（来自 ebpf_event_log 表）"""
    timestamp: int           # 纳秒级 Unix 时间戳
    event_type: EbpfEventType
    memory_addr: Optional[str] = None
    function_name: Optional[str] = None

    model_config = {"from_attributes": True}


class VulnerabilityOut(BaseModel):
    """漏洞条目，内嵌其对应的 eBPF 事件日志（来自 vulnerability 表 + ebpf_event_log 表）"""
    id: uuid.UUID
    vuln_type: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    code_context: Optional[str] = None
    verify_status: VerifyStatus
    ebpf_logs: List[EbpfLogOut] = []

    model_config = {"from_attributes": True}


class ReportOut(BaseModel):
    """终极审计报告：聚合了 task + component_risk + vulnerability + ebpf_event_log 四张表"""
    summary: ReportSummary
    components: List[ComponentOut]
    vulnerabilities: List[VulnerabilityOut]


# ══════════════════════════════════════════════════════════════════════
# API 6: WS /api/v1/ws/tasks/{task_id}/progress WebSocket 推送格式
# ══════════════════════════════════════════════════════════════════════

class WsProgressMessage(BaseModel):
    """WebSocket 实时进度推送的 JSON 格式（不经过全局 HTTP 响应包装器）"""
    stage: str        # 当前阶段: pending / analyzing_deps / llm_auditing / fuzzing
    percent: int      # 总体进度百分比 0~100
    message: str      # 人类可读的当前动作描述
    log_stream: str   # 高频终端刷屏日志（直接透传，不落库）
