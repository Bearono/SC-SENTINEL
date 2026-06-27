<template>
  <div class="page-progress">
    <div class="prh">
      <div>
        <div class="ph">Live Monitor</div>
        <div class="tmeta">
          <span>{{ task?.project_name || '加载中…' }}</span>
          <span class="mono">{{ shortId }}</span>
          <span>{{ liveStatusLabel }}</span>
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

// ── 平滑进度：用本地插值避免进度条跳变 ──────────────────────────────
const displayPercent = ref(0)          // 前端展示值（缓慢插值）
const targetPercent  = ref(0)          // 服务端真实值
let   tweenTimer: ReturnType<typeof setInterval> | null = null

function startTween() {
  if (tweenTimer) return
  tweenTimer = setInterval(() => {
    const diff = targetPercent.value - displayPercent.value
    if (diff <= 0) return
    // 每 80ms 最多走 diff 的 12%，最小步长 0.4，最大步长 2
    const step = Math.min(2, Math.max(0.4, diff * 0.12))
    displayPercent.value = Math.min(targetPercent.value, displayPercent.value + step)
  }, 80)
}
function stopTween() {
  if (tweenTimer) { clearInterval(tweenTimer); tweenTimer = null }
}

// ── 模拟日志行（阶段切换时注入，让 log stream 看起来持续更新）──────
const simLogs = ref<{ time: string; text: string; cls: string }[]>([])
const SIM_LINES: Record<string, string[]> = {
  sbom: [
    '▶ 解析源码依赖树 (CMakeLists / conanfile / vcpkg)…',
    '▶ 提取 #include 引用，推断第三方库列表…',
    '▶ 查询 OSV 数据库，匹配已知 CVE…',
    '▶ 查询 NVD 数据库，补充 CVSS 评分…',
    '▶ 过滤低置信度匹配项，计算风险等级…',
    '✅ SBOM 依赖分析完成，正在汇总组件风险…',
  ],
  llm: [
    '▶ 按函数粒度切片源码 (Agent B)…',
    '▶ 生成漏洞假设，优先检测 UAF / Double-Free / Overflow…',
    '▶ [Agent C] 静态规则预筛，剔除低风险片段…',
    '▶ [Agent D] 调用 LLM 对高风险函数进行语义审计…',
    '▶ [Agent D] LLM 推理中，分析函数间数据流…',
    '▶ [Agent E] 为高置信漏洞生成 Fuzzing Harness…',
    '▶ [Agent F] 归因动态证据，关联静态发现…',
    '▶ [Agent G] 汇总七 Agent 输出，生成最终裁决…',
    '✅ LLM 语义审计完成，漏洞报告已生成…',
  ],
  fuzzing: [
    '▶ 初始化 AFL++ 沙箱环境…',
    '▶ 加载 Harness，注入 eBPF uprobe 探针…',
    '▶ AFL++ 模糊测试运行中，监控内存异常…',
    '▶ eBPF 捕获内核级事件，关联崩溃堆栈…',
  ],
}
let simIndex   = 0
let simStage   = ''
let simLineTimer: ReturnType<typeof setInterval> | null = null
const pageLoadTime = Date.now()

// ── 禁用模拟日志注入 ────────────────────────────────────────────────
function injectSimLogs(stage: string) {
  // 模拟日志已禁用，完全依赖后端真实日志流
  return
}

const wsConnected = computed(() => store.wsConnected)
const percent     = computed(() => Math.round(displayPercent.value))
const shortId     = computed(() => taskId.slice(0, 8))

const isCompleted = computed(() => task.value?.status === 'completed' || store.progressStage === 'done')
const isFailed    = computed(() => task.value?.status === 'failed' || store.progressStage === 'failed')
const isRunning   = computed(() => !isCompleted.value && !isFailed.value)

// 实时阶段描述
const liveStatusLabel = computed(() => {
  const st = task.value?.status
  if (st === 'completed') return '✓ 审计完成'
  if (st === 'failed') return '✕ 任务失败'
  if (st === 'pending') return '⧗ 排队等待中'
  if (st === 'analyzing_deps') return '▶ Agent A — 依赖风险扫描中'
  if (st === 'llm_auditing') return '▶ Agent B-G — LLM 语义审计中'
  if (st === 'fuzzing') return '▶ AFL++ + eBPF 动态验证中'
  return statusLabel.value || '正在处理...'
})

// ── 日志流：展示真实WS消息 + 轮询时的阶段提示 ────────────────────
const logLines = computed(() => {
  const out: { time: string; text: string; cls: string }[] = []

  // 后端WebSocket日志
  for (const log of store.progressLogs) {
    const t = log.timestamp ? new Date(log.timestamp).toLocaleTimeString('en-GB') : ''
    if (log.message) out.push({ time: t, text: log.message, cls: lineClass(log.stage, log.message) })
    if (log.log_stream) {
      for (const raw of log.log_stream.split('\n')) {
        if (raw.trim()) out.push({ time: t, text: raw, cls: lineClass(log.stage, raw) })
      }
    }
  }

  // 如果没有WS日志且任务正在运行，显示轮询状态
  if (out.length === 0 && isRunning.value) {
    const now = new Date().toLocaleTimeString('en-GB')
    const st = task.value?.status
    if (st === 'pending') {
      out.push({ time: now, text: '⧗ 任务已提交，等待调度...', cls: 'lok' })
    } else if (st === 'analyzing_deps') {
      out.push({ time: now, text: '▶ Agent A 正在扫描依赖风险，解析 SBOM...', cls: 'linf' })
    } else if (st === 'llm_auditing') {
      out.push({ time: now, text: '▶ Agent B-G 正在进行语义审计，分析源码切片...', cls: 'linf' })
    } else if (st === 'fuzzing') {
      out.push({ time: now, text: '▶ AFL++ 模糊测试运行中，eBPF 监控内核事件...', cls: 'linf' })
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

// ── 五阶段流水线状态推导 ─────────────────────────────────────────
const stages = computed(() => {
  const dynamic = task.value?.is_dynamic ?? true
  // 当前运行阶段索引：0 deps, 1 slicing, 2 harness, 3 fuzz, 4 report
  let idx = 0
  const st = task.value?.status
  const pct = percent.value

  if (st === 'analyzing_deps') idx = 0
  else if (st === 'llm_auditing') {
    // 根据进度区分是分片阶段还是harness生成阶段
    idx = pct < 40 ? 1 : 2
  }
  else if (st === 'fuzzing') idx = 3
  else if (st === 'completed') idx = 5
  else if (st === 'pending') idx = -1

  // WS percent 兜底
  if (idx < 5 && pct >= 100) idx = 5

  const rows = [
    { key: 'deps', name: 'Agent A — Dependency Risk Scan', descDone: '完成 · SBOM 依赖 CVE 扫描', descRun: '正在解析依赖树，比对 NVD/OSV…', descWait: '等待调度' },
    { key: 'slicing', name: 'Agent B-C — Code Slicing & Triage', descDone: '完成 · 源码切片与静态预审', descRun: '正在按函数切片源码，应用静态规则预筛…', descWait: '等待依赖分析完成' },
    { key: 'harness', name: 'Agent D-E — Harness Generation', descDone: '完成 · Fuzzing Harness 已生成', descRun: 'LLM 语义审计中，为可疑漏洞生成 Harness…', descWait: '等待切片完成' },
    { key: 'fuzz', name: 'AFL++ + eBPF — Dynamic Verification', descDone: '完成 · 动态验证结束', descRun: 'AFL++ fuzzing · eBPF uprobe 监控中…', descWait: dynamic ? '等待 Harness 生成' : '已跳过（未启用动态验证）' },
    { key: 'report', name: 'Agent F-G — Final Report', descDone: '完成 · 最终报告已生成', descRun: '正在汇总七 Agent 输出，生成风险裁决报告…', descWait: '等待验证完成' }
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
    // 始终同步服务端真实百分比到 targetPercent，tween 负责平滑展示
    const serverPct = a.data.data.progress_percent ?? 0
    if (serverPct > targetPercent.value) {
      targetPercent.value = serverPct
    }
    // 根据当前 status 注入模拟日志行
    const st = resp.data.data.status
    if (st === 'analyzing_deps') injectSimLogs('sbom')
    else if (st === 'llm_auditing') injectSimLogs('llm')
    else if (st === 'fuzzing') injectSimLogs('fuzzing')
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

// WS 推送时同步 targetPercent + 触发对应阶段模拟日志
watch(() => store.progressPercent, (v) => {
  if (v > targetPercent.value) targetPercent.value = v
})
watch(() => store.progressStage, (stage) => {
  if (stage && SIM_LINES[stage]) injectSimLogs(stage)
})
let redirectScheduled = false
watch(isCompleted, (done) => {
  if (done && !redirectScheduled) {
    redirectScheduled = true
    if (pollTimer) { clearInterval(pollTimer); pollTimer = null }
    setTimeout(() => { if (route.name === 'monitor') goReport() }, 3500)
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
  startTween()
  pollTimer = setInterval(refreshStatus, 2000)
})
onUnmounted(() => {
  disconnect()
  stopTween()
  if (pollTimer) clearInterval(pollTimer)
  if (simLineTimer) clearInterval(simLineTimer)
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
.linfo { color: #94a3b8; }
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
