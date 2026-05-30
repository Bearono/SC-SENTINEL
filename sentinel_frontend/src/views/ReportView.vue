<template>
  <div class="report-page">
    <!-- 加载状态 -->
    <div v-if="loading" class="loading-fullpage">
      <el-skeleton :rows="6" animated style="max-width: 900px; margin: 60px auto; padding: 0 24px;" />
    </div>

    <!-- 审计进行中 -->
    <div v-else-if="isRunning" class="progress-fullpage">
      <div class="progress-panel sentinel-card">
        <h2 class="progress-title">
          <el-icon class="spin-icon"><Loading /></el-icon>
          审计进行中
        </h2>
        <p class="progress-project">{{ store.currentTask?.project_name }}</p>

        <el-progress
          :percentage="store.progressPercent"
          :stroke-width="8"
          striped
          striped-flow
          color="var(--sentinel-primary-light)"
          style="margin: 24px 0 8px;"
        />
        <div class="progress-stage-label">
          <strong>{{ store.progressStage }}</strong>
          &nbsp;—&nbsp;{{ store.progressMessage }}
        </div>

        <!-- 终端日志流 -->
        <div ref="logBoxRef" class="terminal-box log-box">
          <div class="terminal-header">审计日志</div>
          <template v-if="store.progressLogs.length === 0">
            <span class="terminal-line terminal-line--info">等待日志输出...</span>
          </template>
          <span
            v-for="(log, i) in store.progressLogs"
            :key="i"
            class="terminal-line"
            :class="logLineClass(log)"
          >
            <span class="log-time">[{{ fmtTime(log.timestamp) }}]</span>
            {{ log.message }}
          </span>
        </div>

        <!-- 强制终止 -->
        <el-button
          type="danger"
          plain
          style="margin-top: 16px; width: 100%;"
          @click="handleCancel"
        >
          <el-icon><CircleClose /></el-icon>
          强制终止任务
        </el-button>
      </div>
    </div>

    <!-- 任务失败 -->
    <div v-else-if="store.currentTask?.status === 'failed'" class="error-page">
      <el-result
        icon="error"
        title="审计任务失败"
        :sub-title="store.currentTask?.error_message || '任务执行过程中发生错误'"
      >
        <template #extra>
          <el-button @click="$router.push('/tasks')">返回任务列表</el-button>
          <el-button type="primary" @click="$router.push('/')">重新提交</el-button>
        </template>
      </el-result>
    </div>

    <!-- 报告主体 -->
    <div v-else-if="report" class="report-layout">
      <!-- ══ 顶部概览卡片 ══ -->
      <div class="overview-bar">
        <div class="container">
          <div
            class="overview-card sentinel-card"
            :class="overviewCardClass"
          >
            <div class="overview-left">
              <div class="overview-title">{{ report.task.project_name }}</div>
              <div class="overview-meta">
                <span><el-icon><Calendar /></el-icon>{{ formatDate(report.task.created_at) }}</span>
                <span v-if="report.task.duration_seconds">
                  <el-icon><Timer /></el-icon>耗时 {{ formatDuration(report.task.duration_seconds) }}
                </span>
                <span>
                  <el-icon><Files /></el-icon>
                  {{ report.task.source_type === 'zip' ? 'ZIP 包' : 'GitHub' }}
                </span>
              </div>
            </div>
            <div class="overview-right">
              <div class="risk-badge" :class="`risk-badge--${overallRisk}`">
                {{ riskLabel(overallRisk) }}风险
              </div>
              <div class="overview-stats">
                <div class="stat-item">
                  <span class="stat-num" :style="{ color: 'var(--sentinel-warning)' }">
                    {{ report.vulnerabilities.length }}
                  </span>
                  <span class="stat-lbl">漏洞</span>
                </div>
                <div class="stat-item">
                  <span class="stat-num" :style="{ color: 'var(--sentinel-primary-light)' }">
                    {{ report.component_risks.length }}
                  </span>
                  <span class="stat-lbl">组件</span>
                </div>
                <div class="stat-item">
                  <span class="stat-num" :style="{ color: 'var(--sentinel-success-light)' }">
                    {{ confirmedCount }}
                  </span>
                  <span class="stat-lbl">已验证</span>
                </div>
              </div>
              <el-button
                type="primary"
                :loading="pdfExporting"
                @click="handleExportPdf"
              >
                <el-icon><Download /></el-icon>
                下载 PDF 报告
              </el-button>
            </div>
          </div>
        </div>
      </div>

      <!-- ══ 双栏布局 ══ -->
      <div class="container report-body">
        <!-- 左侧目录 -->
        <aside class="report-toc">
          <div class="toc-inner">
            <div class="toc-title">目录</div>
            <nav>
              <a
                v-for="sec in sections"
                :key="sec.id"
                :href="`#${sec.id}`"
                class="toc-item"
                :class="{ active: activeSection === sec.id }"
                @click.prevent="scrollToSection(sec.id)"
              >
                <span class="toc-dot" />
                {{ sec.label }}
              </a>
            </nav>
          </div>
        </aside>

        <!-- 右侧内容 -->
        <main class="report-content">

          <!-- ① 执行摘要 -->
          <section id="summary" class="report-section">
            <h2 class="section-heading">执行摘要</h2>
            <div class="charts-grid">
              <div class="sentinel-card chart-card">
                <div class="chart-title">漏洞类型分布</div>
                <v-chart :option="vulnTypeChartOption" autoresize style="height: 220px;" />
              </div>
              <div class="sentinel-card chart-card">
                <div class="chart-title">危险等级分布</div>
                <v-chart :option="severityChartOption" autoresize style="height: 220px;" />
              </div>
            </div>
            <div class="summary-text sentinel-card">
              <p>
                本次审计共扫描 <strong>{{ report.component_risks.length }}</strong> 个依赖组件，
                发现 <strong>{{ report.vulnerabilities.length }}</strong> 个漏洞，
                其中 <span class="text-danger">{{ criticalHighCount }}</span> 个为高危/严重漏洞。
                <span v-if="report.task.is_dynamic">
                  动态 Fuzzing 验证已确认 <span class="text-success">{{ confirmedCount }}</span> 个漏洞可实际触发。
                </span>
              </p>
            </div>
          </section>

          <!-- ② 组件风险 (SBOM) -->
          <section id="sbom" class="report-section">
            <h2 class="section-heading">组件风险清单</h2>
            <el-table
              :data="report.component_risks"
              style="width: 100%"
              empty-text="未发现已知 CVE 风险"
            >
              <el-table-column label="库名" prop="library_name" min-width="130" />
              <el-table-column label="版本" prop="version" width="110">
                <template #default="{ row }">
                  <code>{{ row.version || 'unknown' }}</code>
                </template>
              </el-table-column>
              <el-table-column label="CVE 编号" width="160">
                <template #default="{ row }">
                  <a
                    v-if="row.cve_id"
                    :href="row.nvd_url || `https://nvd.nist.gov/vuln/detail/${row.cve_id}`"
                    target="_blank"
                    class="cve-link"
                  >
                    {{ row.cve_id }}
                    <el-icon style="font-size: 10px;"><Link /></el-icon>
                  </a>
                  <span v-else class="text-muted">—</span>
                </template>
              </el-table-column>
              <el-table-column label="CVSS" width="80">
                <template #default="{ row }">
                  <span :class="cvssClass(row.cvss_score)">{{ row.cvss_score ?? '—' }}</span>
                </template>
              </el-table-column>
              <el-table-column label="等级" width="90">
                <template #default="{ row }">
                  <span :class="`badge severity-${row.severity}`">{{ row.severity?.toUpperCase() }}</span>
                </template>
              </el-table-column>
              <el-table-column label="描述" prop="description" min-width="200" show-overflow-tooltip />
            </el-table>
          </section>

          <!-- ③ 漏洞清单 -->
          <section id="vulns" class="report-section">
            <h2 class="section-heading">漏洞清单</h2>
            <div class="vuln-cards">
              <div
                v-for="vuln in report.vulnerabilities"
                :key="vuln.id"
                class="vuln-card sentinel-card"
              >
                <div class="vuln-header">
                  <span :class="`badge severity-${vuln.severity}`">{{ vuln.severity?.toUpperCase() }}</span>
                  <span class="badge badge--pending" style="font-family: 'JetBrains Mono', monospace; font-size: 11px;">
                    {{ vulnTypeLabel(vuln.vuln_type) }}
                  </span>
                  <code class="file-location">
                    {{ vuln.file_path || 'unknown' }}
                    <span v-if="vuln.line_number" class="line-num">:{{ vuln.line_number }}</span>
                  </code>
                </div>

                <!-- 代码高亮块 -->
                <div v-if="vuln.code_snippet" class="code-block-wrapper">
                  <pre><code
                    v-html="highlightCode(vuln.code_snippet, vuln.line_number)"
                  /></pre>
                </div>

                <div class="vuln-details">
                  <div v-if="vuln.description" class="vuln-field">
                    <div class="field-label">漏洞描述</div>
                    <div class="field-value">{{ vuln.description }}</div>
                  </div>
                  <div v-if="vuln.trigger_condition" class="vuln-field">
                    <div class="field-label">触发条件</div>
                    <div class="field-value">{{ vuln.trigger_condition }}</div>
                  </div>
                  <div v-if="vuln.fix_suggestion" class="vuln-field fix-field">
                    <div class="field-label">
                      <el-icon><CircleCheck /></el-icon> 修复建议
                    </div>
                    <div class="field-value">{{ vuln.fix_suggestion }}</div>
                  </div>
                </div>
              </div>

              <el-empty v-if="report.vulnerabilities.length === 0" description="未发现代码漏洞" />
            </div>
          </section>

          <!-- ④ 动态验证结果 (eBPF + AFL++) -->
          <section id="dynamic" class="report-section">
            <h2 class="section-heading">动态验证结果</h2>
            <div v-if="!report.task.is_dynamic" class="sentinel-card" style="padding: 24px; color: var(--text-muted); text-align: center;">
              本次审计未启用动态验证（eBPF + AFL++）
            </div>
            <div v-else class="dynamic-results">
              <div
                v-for="vuln in verifiedVulns"
                :key="vuln.id"
                class="dynamic-card sentinel-card"
              >
                <div class="dynamic-header">
                  <span :class="verifyBadgeClass(vuln.verify_status)">
                    {{ verifyLabel(vuln.verify_status) }}
                  </span>
                  <span class="vuln-type-label">{{ vulnTypeLabel(vuln.vuln_type) }}</span>
                </div>

                <!-- AFL++ 崩溃输出 -->
                <el-collapse v-if="vuln.crash_output">
                  <el-collapse-item title="AFL++ 崩溃输出" name="crash">
                    <div class="terminal-box" style="max-height: 200px;">
                      <span
                        v-for="(line, i) in vuln.crash_output.split('\n')"
                        :key="i"
                        class="terminal-line"
                      >{{ line }}</span>
                    </div>
                  </el-collapse-item>
                </el-collapse>

                <!-- eBPF 内核事件日志 -->
                <div v-if="vuln.vuln_type" class="ebpf-logs">
                  <div class="ebpf-log-title">
                    <el-icon><DataAnalysis /></el-icon>
                    eBPF 内核事件（{{ ebpfEventsForVuln(vuln).length }} 条）
                  </div>
                  <div ref="ebpfLogRef" class="terminal-box ebpf-box">
                    <div class="terminal-header">bpftrace uprobe 监控日志</div>
                    <template v-if="ebpfEventsForVuln(vuln).length === 0">
                      <span class="terminal-line terminal-line--info">未捕获到相关内核事件</span>
                    </template>
                    <span
                      v-for="ev in ebpfEventsForVuln(vuln)"
                      :key="ev.id"
                      class="terminal-line"
                      :class="ebpfLineClass(ev.event_type)"
                    >
                      <span class="log-time">[{{ fmtTime(ev.captured_at) }}]</span>
                      <span class="ebpf-event-type">{{ ev.event_type?.toUpperCase() }}</span>
                      {{ ev.details || ev.raw_log || '' }}
                    </span>
                  </div>
                </div>
              </div>

              <div v-if="verifiedVulns.length === 0" class="sentinel-card" style="padding: 24px; color: var(--text-muted); text-align: center;">
                暂无动态验证结果
              </div>
            </div>
          </section>

        </main>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted, nextTick, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessageBox, ElMessage } from 'element-plus'
import {
  Loading, CircleClose, Calendar, Timer, Files, Download,
  Link, CircleCheck, DataAnalysis
} from '@element-plus/icons-vue'
import VChart from 'vue-echarts'
import { use } from 'echarts/core'
import { CanvasRenderer } from 'echarts/renderers'
import { PieChart, BarChart } from 'echarts/charts'
import { TooltipComponent, LegendComponent, GridComponent } from 'echarts/components'
import hljs from 'highlight.js/lib/core'
import c from 'highlight.js/lib/languages/c'
import 'highlight.js/styles/atom-one-dark.css'

import { getTask, getTaskReport, cancelTask, exportPdf } from '@/api/tasks'
import { useWebSocket } from '@/composables/useWebSocket'
import { useTaskStore } from '@/stores/taskStore'
import type { AuditReport, Vulnerability, EbpfEventLog, WsProgressMessage } from '@/types/api'

// ── ECharts 按需引入 ──────────────────────────────────────────────
use([CanvasRenderer, PieChart, BarChart, TooltipComponent, LegendComponent, GridComponent])
hljs.registerLanguage('c', c)

const route  = useRoute()
const router = useRouter()
const store  = useTaskStore()
const taskId = route.params.id as string

const loading     = ref(true)
const pdfExporting = ref(false)
const report      = ref<AuditReport | null>(null)
const activeSection = ref('summary')
const logBoxRef   = ref<HTMLElement | null>(null)
const ebpfLogRef  = ref<HTMLElement | null>(null)

// ── WebSocket & 轮询 ─────────────────────────────────────────────
const { connect, disconnect } = useWebSocket(taskId)
let pollTimer: ReturnType<typeof setInterval> | null = null

// ── 计算：是否正在审计中 ──────────────────────────────────────────
const isRunning = computed(() => {
  const s = store.currentTask?.status
  return s && !['completed', 'failed'].includes(s)
})

// ── 初始化 ───────────────────────────────────────────────────────
onMounted(async () => {
  store.resetProgress()
  await loadTaskStatus()
  if (isRunning.value) {
    connect()
    startPolling()
  } else if (store.currentTask?.status === 'completed') {
    await loadReport()
  }
  setupScrollSpy()
})

onUnmounted(() => {
  disconnect()
  if (pollTimer) clearInterval(pollTimer)
  window.removeEventListener('scroll', handleScroll)
})

// 任务完结后自动加载报告，销毁 WS + 轮询
watch(() => store.currentTask?.status, async (newStatus) => {
  if (newStatus === 'completed') {
    disconnect()
    if (pollTimer) { clearInterval(pollTimer); pollTimer = null }
    await loadReport()
  }
})

// 日志流自动滚动到底部
watch(() => store.progressLogs.length, async () => {
  await nextTick()
  if (logBoxRef.value) {
    logBoxRef.value.scrollTop = logBoxRef.value.scrollHeight
  }
})

// ── API 调用 ─────────────────────────────────────────────────────
async function loadTaskStatus() {
  loading.value = true
  try {
    const resp = await getTask(taskId)
    store.setCurrentTask(resp.data.data)
  } finally {
    loading.value = false
  }
}

async function loadReport() {
  loading.value = true
  try {
    const resp = await getTaskReport(taskId)
    report.value = resp.data.data
    store.setCurrentReport(resp.data.data)
  } finally {
    loading.value = false
  }
}

function startPolling() {
  pollTimer = setInterval(async () => {
    try {
      const resp = await getTask(taskId)
      store.setCurrentTask(resp.data.data)
    } catch { /* 忽略轮询错误 */ }
  }, 3000)
}

// ── 导出 PDF ─────────────────────────────────────────────────────
async function handleExportPdf() {
  pdfExporting.value = true
  try {
    const resp = await exportPdf(taskId)
    const blob = new Blob([resp.data], { type: 'application/pdf' })
    const url  = URL.createObjectURL(blob)
    const a    = document.createElement('a')
    a.href     = url
    a.download = `SENTINEL_Report_${report.value?.task.project_name ?? taskId}.pdf`
    a.click()
    URL.revokeObjectURL(url)
    ElMessage.success('PDF 报告已下载')
  } finally {
    pdfExporting.value = false
  }
}

// ── 强制取消 ─────────────────────────────────────────────────────
async function handleCancel() {
  try {
    await ElMessageBox.confirm('确认强制终止该审计任务？', '强制终止', {
      confirmButtonText: '确认', cancelButtonText: '取消', type: 'warning'
    })
    await cancelTask(taskId)
    ElMessage.success('任务已强制终止')
    store.currentTask && (store.currentTask.status = 'failed')
  } catch { /* 用户取消 */ }
}

// ── 锚点目录 ─────────────────────────────────────────────────────
const sections = [
  { id: 'summary', label: '执行摘要' },
  { id: 'sbom',    label: '组件风险' },
  { id: 'vulns',   label: '漏洞清单' },
  { id: 'dynamic', label: '动态验证结果' }
]

function scrollToSection(id: string) {
  document.getElementById(id)?.scrollIntoView({ behavior: 'smooth', block: 'start' })
  activeSection.value = id
}

function setupScrollSpy() {
  window.addEventListener('scroll', handleScroll, { passive: true })
}

function handleScroll() {
  for (const sec of [...sections].reverse()) {
    const el = document.getElementById(sec.id)
    if (el && el.getBoundingClientRect().top <= 120) {
      activeSection.value = sec.id
      break
    }
  }
}

// ── ECharts 选项 ─────────────────────────────────────────────────
const vulnTypeChartOption = computed(() => {
  if (!report.value) return {}
  const count: Record<string, number> = {}
  for (const v of report.value.vulnerabilities) {
    const label = vulnTypeLabel(v.vuln_type)
    count[label] = (count[label] ?? 0) + 1
  }
  return {
    backgroundColor: 'transparent',
    tooltip: { trigger: 'item', formatter: '{b}: {c} ({d}%)' },
    legend: { orient: 'vertical', right: '5%', top: 'center', textStyle: { color: '#8fa3b8', fontSize: 12 } },
    series: [{
      type: 'pie',
      radius: ['45%', '70%'],
      center: ['38%', '50%'],
      data: Object.entries(count).map(([name, value]) => ({ name, value })),
      itemStyle: { borderRadius: 4 },
      label: { show: false },
      color: ['#ef9f27', '#e5534b', '#1d9e75', '#5baaff', '#a78bfa']
    }]
  }
})

const severityChartOption = computed(() => {
  if (!report.value) return {}
  const order = ['critical', 'high', 'medium', 'low', 'unknown']
  const colorMap: Record<string, string> = {
    critical: '#b91c1c', high: '#e5534b', medium: '#ef9f27',
    low: '#1d9e75', unknown: '#566b80'
  }
  const count: Record<string, number> = {}
  for (const v of report.value.vulnerabilities) {
    count[v.severity] = (count[v.severity] ?? 0) + 1
  }
  const categories = order.filter(k => count[k])
  return {
    backgroundColor: 'transparent',
    tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
    grid: { left: '3%', right: '8%', bottom: '10%', top: '5%', containLabel: true },
    xAxis: { type: 'category', data: categories.map(k => k.toUpperCase()), axisLabel: { color: '#8fa3b8', fontSize: 11 }, axisLine: { lineStyle: { color: 'rgba(255,255,255,0.1)' } } },
    yAxis: { type: 'value', splitLine: { lineStyle: { color: 'rgba(255,255,255,0.06)' } }, axisLabel: { color: '#8fa3b8' } },
    series: [{
      type: 'bar',
      barMaxWidth: 40,
      borderRadius: [4, 4, 0, 0],
      data: categories.map(k => ({ value: count[k], itemStyle: { color: colorMap[k] } })),
      label: { show: true, position: 'top', color: '#8fa3b8', fontSize: 11 }
    }]
  }
})

// ── 代码高亮 + 漏洞行标红 ────────────────────────────────────────
function highlightCode(code: string, vulnLine: number | null): string {
  const highlighted = hljs.highlight(code, { language: 'c' }).value
  if (!vulnLine) return highlighted

  // 按行切割并对目标行注入红色高亮 class
  const lines = highlighted.split('\n')
  // vulnLine 是原始文件行号，code_snippet 是 ±5 行上下文
  // 我们假设 snippet 的第 5 行（索引 4）是漏洞行
  const relativeIdx = Math.min(4, lines.length - 1)
  lines[relativeIdx] = `<span class="code-line--vuln">${lines[relativeIdx]}</span>`
  return lines.join('\n')
}

// ── 工具函数 ─────────────────────────────────────────────────────
const overallRisk = computed<'critical' | 'high' | 'medium' | 'low'>(() => {
  if (!report.value) return 'low'
  const has = (s: string) => report.value!.vulnerabilities.some(v => v.severity === s)
  if (has('critical')) return 'critical'
  if (has('high'))     return 'high'
  if (has('medium'))   return 'medium'
  return 'low'
})

const overviewCardClass = computed(() => ({
  'sentinel-card--danger': ['critical', 'high'].includes(overallRisk.value)
}))

const criticalHighCount = computed(() =>
  report.value?.vulnerabilities.filter(v => ['critical', 'high'].includes(v.severity)).length ?? 0
)

const confirmedCount = computed(() =>
  report.value?.vulnerabilities.filter(v => v.verify_status === 'confirmed').length ?? 0
)

const verifiedVulns = computed<Vulnerability[]>(() =>
  report.value?.vulnerabilities.filter(v => v.verify_status !== 'pending') ?? []
)

function ebpfEventsForVuln(vuln: Vulnerability): EbpfEventLog[] {
  return report.value?.ebpf_events ?? []
}

function riskLabel(r: string) {
  const m: Record<string, string> = { critical: '严重', high: '高', medium: '中', low: '低' }
  return m[r] ?? '未知'
}

function vulnTypeLabel(t: string | null) {
  const m: Record<string, string> = {
    uaf: 'Use-After-Free', heap_overflow: '堆溢出',
    double_free: 'Double Free', stack_overflow: '栈溢出', other: '其他'
  }
  return (t && m[t]) ? m[t] : (t ?? 'Unknown')
}

function verifyLabel(s: string | null) {
  const m: Record<string, string> = { confirmed: '✓ 已确认', not_triggered: '— 未触发', pending: '⋯ 待验证' }
  return (s && m[s]) ? m[s] : s ?? ''
}

function verifyBadgeClass(s: string | null) {
  if (s === 'confirmed') return 'badge badge--completed'
  if (s === 'not_triggered') return 'badge badge--pending'
  return 'badge badge--running'
}

function ebpfLineClass(type: string | null) {
  if (type === 'double_free' || type === 'uaf_suspected') return 'terminal-line--error'
  if (type === 'alloc') return 'terminal-line--info'
  if (type === 'free')  return 'terminal-line--warn'
  return 'terminal-line--info'
}

function cvssClass(score: number | null) {
  if (!score) return 'text-muted'
  if (score >= 9) return 'text-danger-strong'
  if (score >= 7) return 'text-danger'
  if (score >= 4) return 'text-warning'
  return 'text-success'
}

function logLineClass(log: WsProgressMessage) {
  if (log.percent >= 100) return 'terminal-line--success'
  if (log.stage?.includes('error') || log.stage?.includes('fail')) return 'terminal-line--error'
  return 'terminal-line--info'
}

function formatDate(d: string) {
  return new Date(d).toLocaleString('zh-CN')
}

function formatDuration(s: number) {
  if (s < 60) return `${Math.round(s)} 秒`
  if (s < 3600) return `${Math.floor(s / 60)} 分 ${Math.round(s % 60)} 秒`
  return `${Math.floor(s / 3600)} 小时 ${Math.floor((s % 3600) / 60)} 分`
}

function fmtTime(ts?: string) {
  if (!ts) return ''
  return new Date(ts).toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit', second: '2-digit' })
}
</script>

<style scoped>
.report-page { min-height: 100vh; padding-bottom: 80px; }
.container { max-width: 1200px; margin: 0 auto; padding: 0 24px; }

/* ── 全屏加载/进度 ── */
.loading-fullpage { padding: 40px 0; }
.progress-fullpage {
  min-height: 80vh;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 40px 24px;
}
.progress-panel {
  width: 100%;
  max-width: 680px;
  padding: 36px;
}
.progress-title {
  display: flex;
  align-items: center;
  gap: 10px;
  font-size: 20px;
  font-weight: 700;
  margin-bottom: 8px;
}
.spin-icon { animation: spin 1.5s linear infinite; color: #5baaff; }
@keyframes spin { to { transform: rotate(360deg); } }
.progress-project { color: var(--text-secondary); margin-bottom: 4px; }
.progress-stage-label { font-size: 13px; color: var(--text-secondary); }
.progress-stage-label strong { color: #5baaff; }
.log-box { height: 240px; margin-top: 20px; }

/* ── 错误页 ── */
.error-page { padding: 80px 24px; }

/* ── 概览卡 ── */
.overview-bar { padding: 28px 0 0; }
.overview-card {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 24px 28px;
  flex-wrap: wrap;
  gap: 20px;
}
.overview-title { font-size: 22px; font-weight: 700; color: var(--text-primary); margin-bottom: 8px; }
.overview-meta { display: flex; align-items: center; gap: 16px; flex-wrap: wrap; }
.overview-meta span { display: flex; align-items: center; gap: 4px; font-size: 13px; color: var(--text-secondary); }
.overview-right { display: flex; align-items: center; gap: 20px; flex-wrap: wrap; }
.overview-stats { display: flex; gap: 20px; }
.stat-item { text-align: center; }
.stat-num { display: block; font-size: 28px; font-weight: 700; line-height: 1.2; }
.stat-lbl { font-size: 12px; color: var(--text-muted); }

/* 总体风险评级徽章 */
.risk-badge {
  padding: 6px 16px;
  border-radius: var(--radius-md);
  font-size: 15px;
  font-weight: 700;
  border: 1px solid;
}
.risk-badge--critical { background: rgba(180,30,30,0.2); color: #f76060; border-color: rgba(180,30,30,0.5); }
.risk-badge--high     { background: rgba(229,83,75,0.15); color: #f07070; border-color: rgba(229,83,75,0.4); }
.risk-badge--medium   { background: rgba(239,159,39,0.15); color: #f5b84a; border-color: rgba(239,159,39,0.4); }
.risk-badge--low      { background: rgba(29,158,117,0.15); color: #40c99a; border-color: rgba(29,158,117,0.4); }

/* ── 双栏布局 ── */
.report-body { display: flex; gap: 28px; margin-top: 28px; align-items: flex-start; }

/* 左侧目录 */
.report-toc { width: 200px; flex-shrink: 0; position: sticky; top: 80px; }
.toc-inner {
  background: var(--bg-card);
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-lg);
  padding: 16px;
}
.toc-title { font-size: 12px; font-weight: 600; color: var(--text-muted); text-transform: uppercase; letter-spacing: 1px; margin-bottom: 10px; }
.toc-item {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 7px 10px;
  font-size: 13px;
  color: var(--text-secondary);
  border-radius: var(--radius-sm);
  cursor: pointer;
  transition: all var(--transition-fast);
  text-decoration: none;
}
.toc-item:hover { color: var(--text-primary); background: rgba(255,255,255,0.05); }
.toc-item.active { color: #5baaff; background: rgba(91,170,255,0.1); }
.toc-dot { width: 5px; height: 5px; border-radius: 50%; background: currentColor; flex-shrink: 0; }

/* 右侧内容 */
.report-content { flex: 1; min-width: 0; display: flex; flex-direction: column; gap: 40px; }
.report-section {}
.section-heading {
  font-size: 20px;
  font-weight: 700;
  color: var(--text-primary);
  margin-bottom: 20px;
  padding-bottom: 10px;
  border-bottom: 1px solid var(--border-subtle);
}

/* 图表 */
.charts-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 16px; }
.chart-card { padding: 16px 20px; }
.chart-title { font-size: 13px; font-weight: 500; color: var(--text-secondary); margin-bottom: 4px; }

.summary-text { padding: 16px 20px; font-size: 14px; color: var(--text-secondary); line-height: 1.8; }
.summary-text strong { color: var(--text-primary); }
.text-danger { color: var(--sentinel-danger); font-weight: 600; }
.text-success { color: var(--sentinel-success-light); font-weight: 600; }

/* CVE 链接 */
.cve-link {
  color: #5baaff;
  display: inline-flex;
  align-items: center;
  gap: 3px;
  font-family: 'JetBrains Mono', monospace;
  font-size: 12px;
}
.cve-link:hover { color: var(--sentinel-warning); }

/* CVSS 颜色 */
.text-danger-strong { color: #f76060; font-weight: 600; }
.text-danger  { color: var(--sentinel-danger); }
.text-warning { color: var(--sentinel-warning); }
.text-success { color: var(--sentinel-success-light); }
.text-muted   { color: var(--text-muted); }

/* 漏洞卡片 */
.vuln-cards { display: flex; flex-direction: column; gap: 20px; }
.vuln-card { padding: 20px 24px; display: flex; flex-direction: column; gap: 14px; }
.vuln-header { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.file-location {
  font-family: 'JetBrains Mono', monospace;
  font-size: 12px;
  color: var(--text-secondary);
  background: rgba(255,255,255,0.05);
  padding: 2px 8px;
  border-radius: var(--radius-sm);
}
.line-num { color: var(--sentinel-warning); }

.vuln-details { display: flex; flex-direction: column; gap: 10px; }
.vuln-field {}
.field-label {
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.8px;
  color: var(--text-muted);
  margin-bottom: 4px;
  display: flex;
  align-items: center;
  gap: 4px;
}
.field-value { font-size: 13px; color: var(--text-secondary); line-height: 1.7; }
.fix-field .field-label { color: var(--sentinel-success-light); }
.fix-field .field-value { color: var(--text-primary); }

/* 动态验证 */
.dynamic-results { display: flex; flex-direction: column; gap: 20px; }
.dynamic-card { padding: 20px 24px; display: flex; flex-direction: column; gap: 14px; }
.dynamic-header { display: flex; align-items: center; gap: 10px; }
.vuln-type-label { font-size: 13px; color: var(--text-secondary); }

.ebpf-logs { display: flex; flex-direction: column; gap: 8px; }
.ebpf-log-title { display: flex; align-items: center; gap: 6px; font-size: 13px; color: var(--text-secondary); }
.ebpf-box { height: 160px; }
.ebpf-event-type {
  font-weight: 600;
  color: var(--sentinel-danger);
  margin-right: 4px;
}
.log-time { color: var(--text-muted); margin-right: 6px; font-size: 11px; }

@media (max-width: 900px) {
  .report-body { flex-direction: column; }
  .report-toc { width: 100%; position: static; }
  .charts-grid { grid-template-columns: 1fr; }
}
</style>
