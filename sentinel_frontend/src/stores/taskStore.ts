import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import type { TaskSummary, AuditReport, WsProgressMessage } from '@/types/api'

export const useTaskStore = defineStore('task', () => {
  // ── 当前查看的单任务 ───────────────────────────────────────────
  const currentTask = ref<TaskSummary | null>(null)
  const currentReport = ref<AuditReport | null>(null)

  // ── WebSocket 进度状态 ──────────────────────────────────────────
  const wsConnected = ref(false)
  const progressPercent = ref(0)
  const progressStage = ref('')
  const progressMessage = ref('')
  const progressLogs = ref<WsProgressMessage[]>([])

  // ── 列表页状态 ──────────────────────────────────────────────────
  const taskList = ref<TaskSummary[]>([])
  const taskTotal = ref(0)

  // ── 计算属性：当前任务是否完结 ─────────────────────────────────
  const isTerminal = computed(() =>
    currentTask.value?.status === 'completed' ||
    currentTask.value?.status === 'failed'
  )

  const isRunning = computed(() =>
    currentTask.value != null &&
    !['completed', 'failed', 'pending'].includes(currentTask.value.status)
  )

  // ── Actions ─────────────────────────────────────────────────────
  function setCurrentTask(task: TaskSummary) {
    currentTask.value = task
  }

  function setCurrentReport(report: AuditReport) {
    currentReport.value = report
  }

  function setTaskList(items: TaskSummary[], total: number) {
    taskList.value = items
    taskTotal.value = total
  }

  function updateTaskStatusInList(taskId: string, status: TaskSummary['status']) {
    const idx = taskList.value.findIndex(t => t.id === taskId)
    if (idx !== -1) {
      taskList.value[idx] = { ...taskList.value[idx], status }
    }
  }

  function pushProgressLog(msg: WsProgressMessage) {
    progressLogs.value.push(msg)
    progressPercent.value = msg.percent
    progressStage.value = msg.stage
    progressMessage.value = msg.message
  }

  function resetProgress() {
    wsConnected.value = false
    progressPercent.value = 0
    progressStage.value = ''
    progressMessage.value = ''
    progressLogs.value = []
  }

  function clear() {
    currentTask.value = null
    currentReport.value = null
    resetProgress()
  }

  return {
    currentTask,
    currentReport,
    wsConnected,
    progressPercent,
    progressStage,
    progressMessage,
    progressLogs,
    taskList,
    taskTotal,
    isTerminal,
    isRunning,
    setCurrentTask,
    setCurrentReport,
    setTaskList,
    updateTaskStatusInList,
    pushProgressLog,
    resetProgress,
    clear
  }
})
