<template>
  <div class="page-progress">
    <div class="prh">
      <div>
        <div class="ph">Live Monitor</div>
        <div class="tmeta">
          <span>{{ task?.project_name || '加载中…' }}</span>
          <span class="mono">{{ shortId }}</span>
          <span>{{ statusLabel }}</span>
        </div>
      </div>
      <div class="pr-actions">
        <button v-if="isCompleted" class="bp bw" style="font-size:12px;padding:7px 15px" @click="goReport">View Report →</button>
        <button v-else class="bp bg" style="font-size:12px;padding:7px 15px" :disabled="!isRunning" @click="handleCancel">Cancel</button>
      </div>
    </div>

    <!-- Live Log -->
    <div class="logcard">
      <div class="lhead">
        <span class="ltit">Live Log Stream</span>
        <div class="llive">
          <span class="lldot" :style="{ background: wsConnected ? '#34d399' : '#f59e0b' }" />
          <span>{{ wsConnected ? 'WebSocket connected' : 'Polling (fallback)' }}</span>
        </div>
      </div>
      <div ref="logBody" class="lbody">
        <div v-if="logLines.length === 0" class="ll"><span class="lts">--:--:--</span><span class="lcur">█ waiting for log stream…</span></div>
        <div v-for="(l, i) in logLines" :key="i" class="ll">
          <span class="lts">{{ l.time }}</span><span :class="l.cls">{{ l.text }}</span>
        </div>
      </div>
    </div>

    <!-- Pipeline -->
    <div class="pp-card">
      <div class="pph"><span class="pptit">Pipeline Progress</span><span class="pppct">{{ percent }}%</span></div>
      <div class="bigbar"><div class="bigfill" :style="{ width: percent + '%' }" /></div>
      <div class="ppstages">
        <div v-for="s in stages" :key="s.key" class="pprow" :class="{ run: s.state === 'run' }">
          <div class="ppico" :class="s.state === 'done' ? 'done' : s.state === 'run' ? 'run2' : 'wait'">
            {{ s.state === 'done' ? '✓' : s.state === 'run' ? '⬡' : '◎' }}
          </div>
          <div class="ppbody">
            <div class="ppn">{{ s.name }}</div>
            <div class="pps">{{ s.desc }}</div>
            <div v-if="s.state === 'run'" class="ppbar"><div class="ppbf" :style="{ width: percent + '%' }" /></div>
          </div>
        </div>
      </div>
    </div>

    <!-- Error -->
    <div v-if="isFailed" class="errcard">
      <div class="errtit">✕ 任务执行失败</div>
      <div class="errmsg">{{ task?.error_message || '任务在执行过程中发生错误' }}</div>
      <div style="margin-top:14px"><button class="bp bg" @click="router.push('/submit')">重新提交</button></div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted, watch, nextTick } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { getTask, cancelTask } from '@/api/tasks'
import { getAuditStatus } from '@/api/audit'
import { useWebSocket } from '@/composables/useWebSocket'
import { useTaskStore } from '@/stores/taskStore'
import type { TaskSummary } from '@/types/api'

const route = useRoute()
const router = useRouter()
const store = useTaskStore()
const taskId = route.params.id as string

const task = ref<TaskSummary | null>(null)
const statusLabel = ref('排队等待中')
const logBody = ref<HTMLElement | null>(null)
const { connect, disconnect } = useWebSocket(taskId)
let pollTimer: ReturnType<typeof setInterval> | null = null

const wsConnected = computed(() => store.wsConnected)
const percent = computed(() => store.progressPercent)
const shortId = computed(() => taskId.slice(0, 8))

const isCompleted = computed(() => task.value?.status === 'completed' || percent.value >= 100)
const isFailed = computed(() => task.value?.status === 'failed' || store.progressStage === 'failed')
const isRunning = computed(() => !isCompleted.value && !isFailed.value)

// ── 日志流：展开每条 WS 消息（message + log_stream 多行）──────────
const logLines = computed(() => {
  const out: { time: string; text: string; cls: string }[] = []
  for (const log of store.progressLogs) {
    const t = log.timestamp ? new Date(log.timestamp).toLocaleTimeString('en-GB') : ''
    if (log.message) out.push({ time: t, text: log.message, cls: lineClass(log.stage, log.message) })
    if (log.log_stream) {
      for (const raw of log.log_stream.split('\n')) {
        if (raw.trim()) out.push({ time: t, text: raw, cls: lineClass(log.stage, raw) })
      }
    }
  }
  return out
})

function lineClass(stage: string, text: string) {
  if (stage === 'failed' || /error|fail|✕|❌/i.test(text)) return 'lwrn'
  if (/eBPF|uprobe|0x/i.test(text)) return 'laddr'
  if (/crash|warn|⚠/i.test(text)) return 'lwrn'
  if (/\[LLM\]|\[AFL/i.test(text)) return 'linf'
  return 'lok'
}

// ── 四阶段流水线状态推导 ─────────────────────────────────────────
const stages = computed(() => {
  const dynamic = task.value?.is_dynamic ?? true
  // 当前运行阶段索引：0 deps, 1 llm, 2 fuzz, 3 report
  let idx = 0
  const st = task.value?.status
  if (st === 'analyzing_deps') idx = 0
  else if (st === 'llm_auditing') idx = 1
  else if (st === 'fuzzing') idx = 2
  else if (st === 'completed') idx = 4
  else if (st === 'pending') idx = -1
  // WS percent 兜底
  if (idx < 4 && percent.value >= 100) idx = 4

  const rows = [
    { key: 'deps', name: 'Agent A — Dependency Risk Scan', descDone: '完成 · SBOM 依赖 CVE 扫描', descRun: '正在解析依赖树，比对 NVD/OSV…', descWait: '等待调度' },
    { key: 'llm', name: 'Agent B — LLM Semantic Audit', descDone: '完成 · 源码语义漏洞审计', descRun: 'LLM 正在按函数切片审计源码…', descWait: '等待依赖分析完成' },
    { key: 'fuzz', name: 'Dynamic Verification — AFL++ + eBPF', descDone: '完成 · 动态验证结束', descRun: 'AFL++ fuzzing · eBPF uprobe 监控中…', descWait: dynamic ? '等待静态审计完成' : '已跳过（未启用动态验证）' },
    { key: 'report', name: 'Agent C — Report Synthesis', descDone: '完成 · 报告已生成', descRun: '正在汇总生成报告…', descWait: '等待验证完成' }
  ]
  return rows.map((r, i) => {
    let state: 'done' | 'run' | 'wait'
    if (!dynamic && r.key === 'fuzz') {
      state = idx >= 2 ? 'done' : 'wait' // 非动态：fuzz 直接视为跳过/完成
    } else if (idx === 4) {
      state = 'done'
    } else if (i < idx) state = 'done'
    else if (i === idx) state = 'run'
    else state = 'wait'
    const desc = state === 'done' ? r.descDone : state === 'run' ? r.descRun : r.descWait
    return { key: r.key, name: r.name, desc, state }
  })
})

// ── 数据加载 ─────────────────────────────────────────────────────
async function refreshStatus() {
  try {
    const resp = await getTask(taskId)
    task.value = resp.data.data
    store.setCurrentTask(resp.data.data)
    const a = await getAuditStatus(taskId)
    statusLabel.value = a.data.data.status_label
    // 无 WS 推送时用轮询百分比兜底
    if (!store.wsConnected && a.data.data.progress_percent >= 0) {
      store.progressPercent = a.data.data.progress_percent
    }
  } catch { /* 忽略轮询错误 */ }
}

async function handleCancel() {
  try {
    await cancelTask(taskId)
    await refreshStatus()
  } catch { /* 拦截器已处理 */ }
}

function goReport() {
  router.push({ name: 'report', params: { id: taskId } })
}

// 自动滚动日志到底
watch(() => logLines.value.length, async () => {
  await nextTick()
  if (logBody.value) logBody.value.scrollTop = logBody.value.scrollHeight
})

// 完成后短暂停留再跳报告（一次性守卫，防止 status/percent 双触发导致重复跳转）
let redirectScheduled = false
watch(isCompleted, (done) => {
  if (done && !redirectScheduled) {
    redirectScheduled = true
    if (pollTimer) { clearInterval(pollTimer); pollTimer = null }
    setTimeout(() => { if (route.name === 'monitor') goReport() }, 1800)
  }
})

// 失败时停止轮询（无需再刷新状态）
watch(isFailed, (failed) => {
  if (failed && pollTimer) { clearInterval(pollTimer); pollTimer = null }
})

onMounted(async () => {
  store.resetProgress()
  await refreshStatus()
  connect()
  pollTimer = setInterval(refreshStatus, 3000)
})
onUnmounted(() => {
  disconnect()
  if (pollTimer) clearInterval(pollTimer)
})
</script>

<style scoped>
.page-progress { max-width: 920px; margin: 0 auto; padding: 72px 44px; }
.prh { display: flex; align-items: flex-start; justify-content: space-between; margin-bottom: 44px; gap: 20px; }
.ph { font-family: var(--fd); font-size: 34px; letter-spacing: -.8px; line-height: 1.1; }
.tmeta { font-size: 12px; color: var(--fog); margin-top: 6px; }
.tmeta span { margin-right: 14px; }
.tmeta .mono { font-family: var(--fm); font-size: 11px; color: var(--fog); }
.pr-actions { display: flex; gap: 8px; align-items: center; }
/* MON2 */
.logcard { background: #141210; border-radius: 16px; overflow: hidden; margin-bottom: 20px; border: 1px solid #2a2520; }
.lhead { padding: 12px 20px; border-bottom: 1px solid #221e19; display: flex; align-items: center; justify-content: space-between; }
.ltit { font-size: 11px; font-weight: 700; color: #665f55; letter-spacing: .5px; text-transform: uppercase; }
.llive { display: flex; align-items: center; gap: 5px; font-size: 11px; color: #6b6359; }
.lldot { width: 5px; height: 5px; border-radius: 50%; background: #34d399; animation: pulse 1s infinite; }
.lbody { padding: 16px 20px; font-family: var(--fm); font-size: 12px; line-height: 1.75; height: 360px; overflow-y: auto; }
.ll { display: flex; gap: 14px; margin-bottom: 1px; }
.lts { color: #3d3730; flex-shrink: 0; min-width: 64px; }
.lok { color: #34d399; }
.linf { color: #60a5fa; }
.lwrn { color: #f59e0b; }
.laddr { color: #c084fc; }
.lcur { color: #4b4540; }
/* MON3 */
.pp-card { background: #fff; border-radius: 20px; border: 1px solid var(--ch); box-shadow: var(--sc); overflow: hidden; margin-bottom: 20px; }
.pph { padding: 20px 24px; border-bottom: 1px solid var(--ch); display: flex; align-items: center; justify-content: space-between; }
.pptit { font-size: 13px; font-weight: 600; }
.pppct { font-family: var(--fd); font-size: 30px; background: linear-gradient(135deg, var(--w1), var(--amber)); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; }
.bigbar { height: 4px; background: var(--ch); }
.bigfill { height: 100%; background: linear-gradient(90deg, var(--w1), var(--amber)); transition: width 1s ease; box-shadow: 0 0 8px rgba(255, 107, 53, .4); }
.ppstages { padding: 6px 0; }
.pprow { display: flex; align-items: center; gap: 16px; padding: 14px 24px; border-bottom: 1px solid var(--ch); transition: background .15s; }
.pprow:last-child { border-bottom: none; }
.pprow.run { background: var(--w4); }
.ppico { width: 36px; height: 36px; border-radius: 9px; border: 1px solid var(--ch); display: flex; align-items: center; justify-content: center; font-size: 15px; flex-shrink: 0; }
.ppico.done { background: linear-gradient(135deg, var(--w1), var(--amber)); color: #fff; border: none; }
.ppico.run2 { background: var(--w4); border-color: rgba(255, 107, 53, .3); animation: blink 1.8s infinite; }
.ppico.wait { background: var(--pw); opacity: .4; }
.ppbody { flex: 1; }
.ppn { font-size: 13px; font-weight: 600; }
.pps { font-size: 11px; color: var(--grv); margin-top: 2px; }
.ppbar { height: 3px; width: 140px; background: var(--ch); border-radius: 9999px; overflow: hidden; margin-top: 6px; }
.ppbf { height: 100%; background: linear-gradient(90deg, var(--w1), var(--amber)); border-radius: 9999px; transition: width 1s ease; }

.errcard { background: var(--rbg); border: 1px solid rgba(201, 59, 42, .25); border-radius: 16px; padding: 22px 24px; }
.errtit { font-size: 14px; font-weight: 700; color: var(--rc); margin-bottom: 8px; }
.errmsg { font-size: 13px; color: var(--grv); line-height: 1.6; font-family: var(--fm); }

@media (max-width: 700px) {
  .page-progress { padding: 48px 18px; }
}
</style>
