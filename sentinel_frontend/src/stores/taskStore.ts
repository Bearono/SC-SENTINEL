import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import type { TaskSummary, AuditReport, WsProgressMessage } from '@/types/api'

const TERMINAL = ['completed', 'failed']
const RUNNING = ['analyzing_deps', 'llm_auditing', 'fuzzing']

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

  // ── 计算属性 ────────────────────────────────────────────────────
  const isTerminal = computed(() =>
    currentTask.value ? TERMINAL.includes(currentTask.value.status) : false
  )

  const isRunning = computed(() =>
    currentTask.value ? RUNNING.includes(currentTask.value.status) || currentTask.value.status === 'pending' : false
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
    const idx = taskList.value.findIndex((t) => t.id === taskId)
    if (idx !== -1) {
      taskList.value[idx] = { ...taskList.value[idx], status }
    }
  }

  function pushProgressLog(msg: WsProgressMessage) {
    progressLogs.value.push({ ...msg, timestamp: new Date().toISOString() })
    if (typeof msg.percent === 'number') progressPercent.value = msg.percent
    if (msg.stage) progressStage.value = msg.stage
    if (msg.message) progressMessage.value = msg.message
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
