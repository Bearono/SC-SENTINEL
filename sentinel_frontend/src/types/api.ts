/**
 * 后端 API 返回数据类型定义
 * 与 app/schemas/ 下的结构一一对应
 */

// ── 通用响应包装 ─────────────────────────────────────────────────
export interface ApiResponse<T = unknown> {
  code: number
  msg: string
  data: T
}

// ── 任务状态枚举（与后端 TaskStatus 一致） ────────────────────────
export type TaskStatus =
  | 'pending'
  | 'sbom_scanning'
  | 'llm_auditing'
  | 'fuzzing'
  | 'completed'
  | 'failed'

export type SourceType = 'zip' | 'github'
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'unknown'
export type VulnType = 'uaf' | 'heap_overflow' | 'double_free' | 'stack_overflow' | 'other'
export type EbpfEventType = 'double_free' | 'uaf_suspected' | 'alloc' | 'free' | 'other'
export type VerifyStatus = 'confirmed' | 'not_triggered' | 'pending'

// ── 任务摘要（列表页） ───────────────────────────────────────────
export interface TaskSummary {
  id: string
  project_name: string
  source_type: SourceType
  status: TaskStatus
  is_dynamic: boolean
  vuln_count: number
  created_at: string
  completed_at: string | null
  error_message: string | null
}

// ── 任务分页列表 ──────────────────────────────────────────────────
export interface TaskListData {
  items: TaskSummary[]
  total: number
  page: number
  page_size: number
}

// ── 组件风险（SBOM 结果） ─────────────────────────────────────────
export interface ComponentRisk {
  id: string
  task_id: string
  library_name: string
  version: string | null
  cve_id: string | null
  cvss_score: number | null
  severity: Severity
  description: string | null
  nvd_url: string | null
}

// ── 漏洞详情 ─────────────────────────────────────────────────────
export interface Vulnerability {
  id: string
  task_id: string
  vuln_type: VulnType
  severity: Severity
  file_path: string | null
  line_number: number | null
  code_snippet: string | null
  description: string | null
  trigger_condition: string | null
  fix_suggestion: string | null
  verify_status: VerifyStatus
  crash_output: string | null
}

// ── eBPF 事件日志 ─────────────────────────────────────────────────
export interface EbpfEventLog {
  id: string
  task_id: string
  event_type: EbpfEventType
  address: string | null
  details: string | null
  raw_log: string | null
  captured_at: string
}

// ── 完整审计报告（四表联查） ──────────────────────────────────────
export interface AuditReport {
  task: TaskSummary & {
    duration_seconds: number | null
  }
  component_risks: ComponentRisk[]
  vulnerabilities: Vulnerability[]
  ebpf_events: EbpfEventLog[]
}

// ── 提交任务的表单 ────────────────────────────────────────────────
export interface SubmitTaskForm {
  project_name: string
  source_type: SourceType
  github_url?: string
  is_dynamic: boolean
  vuln_types?: VulnType[]
}

// ── WebSocket 进度推送 ────────────────────────────────────────────
export interface WsProgressMessage {
  stage: string
  percent: number
  message: string
  timestamp?: string
}
