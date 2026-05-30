<template>
  <div class="task-list-page">
    <div class="container">
      <div class="page-header">
        <h1 class="page-title">任务列表</h1>
        <el-button type="primary" @click="$router.push('/')">
          <el-icon><Plus /></el-icon>
          新建审计
        </el-button>
      </div>

      <!-- 搜索 + 筛选栏 -->
      <div class="toolbar sentinel-card">
        <el-input
          v-model="filters.project_name"
          placeholder="按项目名搜索..."
          :prefix-icon="Search"
          clearable
          style="width: 260px"
          @input="handleFilterChange"
        />
        <el-select
          v-model="filters.status"
          placeholder="全部状态"
          clearable
          style="width: 160px"
          @change="handleFilterChange"
        >
          <el-option label="全部状态" value="" />
          <el-option label="待处理" value="pending" />
          <el-option label="审计中" value="sbom_scanning" />
          <el-option label="已完成" value="completed" />
          <el-option label="失败" value="failed" />
        </el-select>
        <el-button :icon="Refresh" circle plain @click="fetchTasks" title="刷新" />
      </div>

      <!-- 任务卡片列表 -->
      <div v-if="loading" class="loading-wrapper">
        <el-skeleton :rows="3" animated v-for="i in 3" :key="i" style="margin-bottom: 16px;" />
      </div>

      <div v-else-if="taskList.length === 0" class="empty-state">
        <el-empty description="暂无审计任务">
          <el-button type="primary" @click="$router.push('/')">上传第一个项目</el-button>
        </el-empty>
      </div>

      <div v-else class="task-cards">
        <div
          v-for="task in taskList"
          :key="task.id"
          class="task-card sentinel-card"
          :class="{ 'sentinel-card--danger': task.status === 'failed' }"
        >
          <div class="task-card-header">
            <div class="task-card-title">
              <span class="task-name">{{ task.project_name }}</span>
              <span :class="statusBadgeClass(task.status)" class="badge">
                <span class="status-dot" :class="`dot--${task.status}`" />
                {{ statusLabel(task.status) }}
              </span>
            </div>
            <div class="task-card-time">
              <el-icon><Clock /></el-icon>
              {{ formatDate(task.created_at) }}
            </div>
          </div>

          <!-- 审计中：显示进度条 + 阶段文字 -->
          <div v-if="isRunning(task.status)" class="task-progress">
            <div class="progress-stage-text">
              <el-icon><Loading /></el-icon>
              {{ stageLabel(task.status) }}
            </div>
            <el-progress
              :percentage="stagePercent(task.status)"
              :stroke-width="4"
              :show-text="false"
              status="striped"
              striped-flow
              color="var(--sentinel-primary-light)"
            />
          </div>

          <!-- 完成：漏洞数 + 危险分布 -->
          <div v-else-if="task.status === 'completed'" class="task-card-stats">
            <div class="vuln-count">
              <el-icon><Bug /></el-icon>
              发现 <strong>{{ task.vuln_count }}</strong> 个漏洞
            </div>
            <div class="source-tag">
              <el-icon><Files /></el-icon>
              {{ task.source_type === 'zip' ? 'ZIP 包' : 'GitHub' }}
            </div>
          </div>

          <!-- 失败：显示错误信息 -->
          <div v-else-if="task.status === 'failed'" class="task-error">
            <el-icon><WarningFilled /></el-icon>
            {{ task.error_message || '任务执行失败' }}
          </div>

          <div class="task-card-footer">
            <el-button
              v-if="task.status === 'completed'"
              type="primary"
              size="small"
              plain
              @click="goToReport(task.id)"
            >
              查看报告
              <el-icon class="el-icon--right"><ArrowRight /></el-icon>
            </el-button>
            <el-button
              v-if="isRunning(task.status)"
              type="danger"
              size="small"
              plain
              @click="handleCancel(task)"
            >
              <el-icon><CircleClose /></el-icon>
              强制终止
            </el-button>
          </div>
        </div>
      </div>

      <!-- 分页 -->
      <div v-if="total > pageSize" class="pagination-wrapper">
        <el-pagination
          v-model:current-page="currentPage"
          :page-size="pageSize"
          :total="total"
          layout="prev, pager, next"
          background
          @current-change="fetchTasks"
        />
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessageBox, ElMessage } from 'element-plus'
import {
  Search, Refresh, Plus, Clock, Loading, Warning, Files,
  WarningFilled, ArrowRight, CircleClose
} from '@element-plus/icons-vue'
import { getTaskList, cancelTask } from '@/api/tasks'
import type { TaskSummary, TaskStatus } from '@/types/api'

const router = useRouter()

const taskList = ref<TaskSummary[]>([])
const total = ref(0)
const currentPage = ref(1)
const pageSize = 10
const loading = ref(false)
let pollTimer: ReturnType<typeof setInterval> | null = null

const filters = ref({ project_name: '', status: '' })

// ── 数据加载 ─────────────────────────────────────────────────────
async function fetchTasks() {
  loading.value = true
  try {
    const resp = await getTaskList({
      page: currentPage.value,
      page_size: pageSize,
      ...(filters.value.project_name ? { project_name: filters.value.project_name } : {}),
      ...(filters.value.status ? { status: filters.value.status } : {})
    })
    taskList.value = resp.data.data.items
    total.value = resp.data.data.total
  } finally {
    loading.value = false
  }
}

function handleFilterChange() {
  currentPage.value = 1
  fetchTasks()
}

// ── 3 秒轮询（MVP 降级策略） ──────────────────────────────────────
function startPolling() {
  pollTimer = setInterval(() => {
    const hasRunning = taskList.value.some(t => isRunning(t.status))
    if (hasRunning) fetchTasks()
  }, 3000)
}

// ── 状态工具函数 ─────────────────────────────────────────────────
function isRunning(status: TaskStatus) {
  return ['sbom_scanning', 'llm_auditing', 'fuzzing'].includes(status)
}

function statusLabel(status: TaskStatus) {
  const map: Record<TaskStatus, string> = {
    pending: '待处理',
    sbom_scanning: 'SBOM 扫描中',
    llm_auditing: 'LLM 审计中',
    fuzzing: 'Fuzzing 中',
    completed: '已完成',
    failed: '失败'
  }
  return map[status] ?? status
}

function stageLabel(status: TaskStatus) {
  const map: Record<string, string> = {
    sbom_scanning: '正在扫描依赖组件，调用 Agent A 分析 CVE...',
    llm_auditing: 'LLM 正在进行源码语义审计...',
    fuzzing: 'AFL++ 正在 Docker 沙箱中进行 Fuzzing 测试...'
  }
  return map[status] ?? '处理中...'
}

function stagePercent(status: TaskStatus) {
  const map: Record<string, number> = {
    sbom_scanning: 25,
    llm_auditing: 60,
    fuzzing: 85
  }
  return map[status] ?? 10
}

function statusBadgeClass(status: TaskStatus) {
  const map: Record<TaskStatus, string> = {
    pending:       'badge--pending',
    sbom_scanning: 'badge--running',
    llm_auditing:  'badge--running',
    fuzzing:       'badge--running',
    completed:     'badge--completed',
    failed:        'badge--failed'
  }
  return map[status]
}

function formatDate(dateStr: string) {
  return new Date(dateStr).toLocaleString('zh-CN', {
    month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit'
  })
}

// ── 导航与操作 ────────────────────────────────────────────────────
function goToReport(taskId: string) {
  router.push({ name: 'report', params: { id: taskId } })
}

async function handleCancel(task: TaskSummary) {
  try {
    await ElMessageBox.confirm(
      `确认强制终止任务「${task.project_name}」？此操作将立即销毁 Docker 沙箱容器。`,
      '强制终止',
      { confirmButtonText: '确认终止', cancelButtonText: '取消', type: 'warning', confirmButtonClass: 'el-button--danger' }
    )
    await cancelTask(task.id)
    ElMessage.success('任务已强制终止')
    fetchTasks()
  } catch {
    // 用户取消或请求失败（拦截器已处理弹窗）
  }
}

onMounted(() => { fetchTasks(); startPolling() })
onUnmounted(() => { if (pollTimer) clearInterval(pollTimer) })
</script>

<style scoped>
.task-list-page { min-height: 100vh; padding: 40px 0 80px; }
.container { max-width: 1100px; margin: 0 auto; padding: 0 24px; }
.page-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 28px;
}
.page-title { font-size: 28px; font-weight: 700; color: var(--text-primary); }

/* 工具栏 */
.toolbar {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 16px 20px;
  margin-bottom: 24px;
  flex-wrap: wrap;
}

/* 任务卡片 */
.task-cards { display: flex; flex-direction: column; gap: 16px; }
.task-card {
  padding: 20px 24px;
  display: flex;
  flex-direction: column;
  gap: 14px;
  transition: transform var(--transition-normal);
}
.task-card:hover { transform: translateX(2px); }

.task-card-header { display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 8px; }
.task-card-title { display: flex; align-items: center; gap: 10px; }
.task-name { font-size: 16px; font-weight: 600; color: var(--text-primary); }
.task-card-time { display: flex; align-items: center; gap: 4px; font-size: 12px; color: var(--text-muted); }

/* 进度条区域 */
.task-progress { display: flex; flex-direction: column; gap: 8px; }
.progress-stage-text {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 13px;
  color: #5baaff;
}
.progress-stage-text .el-icon { animation: spin 1.5s linear infinite; }
@keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }

/* 统计区 */
.task-card-stats, .task-error {
  display: flex;
  align-items: center;
  gap: 16px;
  font-size: 13px;
  color: var(--text-secondary);
}
.vuln-count strong { color: var(--sentinel-warning); }
.task-error { color: var(--sentinel-danger); }
.source-tag { display: flex; align-items: center; gap: 4px; }

/* 底部按钮行 */
.task-card-footer { display: flex; gap: 8px; }

/* 状态点 */
.status-dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  display: inline-block;
}
.dot--sbom_scanning, .dot--llm_auditing, .dot--fuzzing {
  background: #5baaff;
  animation: blink 1.2s ease-in-out infinite;
}
.dot--completed { background: var(--sentinel-success-light); }
.dot--failed    { background: var(--sentinel-danger); }
.dot--pending   { background: var(--text-muted); }
@keyframes blink { 0%, 100% { opacity: 1; } 50% { opacity: 0.3; } }

/* 空状态 / 分页 */
.loading-wrapper { display: flex; flex-direction: column; gap: 12px; }
.empty-state { padding: 60px 0; }
.pagination-wrapper { display: flex; justify-content: center; margin-top: 32px; }
</style>
