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
from app.models.task import SourceType, TaskStatus
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
    """任务列表中的单条摘要（含前端列表页所需的全部展示字段）"""
    id: uuid.UUID
    project_name: str
    status: TaskStatus
    source_type: SourceType
    is_dynamic: bool
    vuln_count: int = 0           # 漏洞总数（completed 后才有意义）
    error_message: Optional[str] = None
    created_at: datetime
    completed_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


class TaskListOut(BaseModel):
    """分页任务列表响应体"""
    total: int
    items: List[TaskListItem]


# ══════════════════════════════════════════════════════════════════════
# API: GET /api/v1/tasks/stats 全局聚合统计（History 仪表盘用）
# ══════════════════════════════════════════════════════════════════════

class LibRiskCount(BaseModel):
    """单个第三方库的 CVE 数量（按等级拆分）"""
    library_name: str
    critical: int = 0
    high: int = 0
    other: int = 0


class DashboardStats(BaseModel):
    """History 仪表盘聚合统计，一次性返回全部 KPI + 图表数据"""
    total_audits: int = 0
    completed: int = 0
    running: int = 0
    failed: int = 0
    total_vulns: int = 0
    cve_risks: int = 0
    confirm_rate: int = 0          # eBPF 动态确认率（百分比，0~100）
    avg_scan_seconds: int = 0      # 平均端到端耗时（秒）
    vuln_type_dist: dict = {}      # { "UAF": 5, "Heap Overflow": 3, ... }
    top_libs: List[LibRiskCount] = []   # 高频漏洞组件 Top N


# ══════════════════════════════════════════════════════════════════════
# API 3: GET /api/v1/tasks/{task_id} 单体状态（轻量级轮询）
# ══════════════════════════════════════════════════════════════════════

class TaskStatusOut(BaseModel):
    """返回完整的任务状态信息，供前端进度页和轮询使用"""
    id: uuid.UUID
    project_name: str
    status: TaskStatus
    source_type: SourceType
    is_dynamic: bool
    vuln_count: int = 0
    error_message: Optional[str] = None
    created_at: datetime
    completed_at: Optional[datetime] = None

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
    cvss_score: Optional[float] = None
    severity: Severity
    description: Optional[str] = None
    nvd_url: Optional[str] = None

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
    description: Optional[str] = None
    trigger_condition: Optional[str] = None
    fix_suggestion: Optional[str] = None
    verify_status: VerifyStatus
    crash_output: Optional[str] = None
    ebpf_logs: List[EbpfLogOut] = []
    llm_original_type: Optional[str] = None  # LLM初始分类(如被eBPF纠正)
    ebpf_corrected: bool = False              # 是否被eBPF纠正

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
