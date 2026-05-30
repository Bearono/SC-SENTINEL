import http from './http'
import type {
  ApiResponse,
  TaskSummary,
  TaskListData,
  AuditReport
} from '@/types/api'

/** 提交审计任务（multipart/form-data） */
export function submitTask(formData: FormData) {
  return http.post<ApiResponse<TaskSummary>>('/tasks', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
    timeout: 60000 // 文件上传允许更长超时
  })
}

/** 获取任务列表（分页 + 筛选） */
export function getTaskList(params: {
  page?: number
  page_size?: number
  status?: string
  project_name?: string
}) {
  return http.get<ApiResponse<TaskListData>>('/tasks', { params })
}

/** 获取单个任务状态 */
export function getTask(taskId: string) {
  return http.get<ApiResponse<TaskSummary>>(`/tasks/${taskId}`)
}

/** 获取完整审计报告（四表联查） */
export function getTaskReport(taskId: string) {
  return http.get<ApiResponse<AuditReport>>(`/tasks/${taskId}/report`)
}

/** 强制终止任务 */
export function cancelTask(taskId: string) {
  return http.post<ApiResponse<null>>(`/tasks/${taskId}/cancel`)
}

/** 导出 PDF 审计报告（返回 Blob） */
export function exportPdf(taskId: string) {
  return http.get(`/tasks/${taskId}/export-pdf`, {
    responseType: 'blob',
    timeout: 120000 // PDF 生成可能需要更多时间
  })
}
