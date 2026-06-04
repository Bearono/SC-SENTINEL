<template>
  <div class="page-report">
    <!-- Loading -->
    <div v-if="loading" class="rload">正在加载审计报告…</div>

    <!-- Not ready (still running) -->
    <div v-else-if="notReady" class="rload">
      <div style="font-size:15px;color:var(--obs);margin-bottom:8px">任务尚未完成</div>
      <div style="font-size:13px;color:var(--grv);margin-bottom:16px">报告将在审计流水线结束后生成</div>
      <button class="bp bw" @click="goMonitor">前往实时监控 →</button>
    </div>

    <!-- Report body -->
    <template v-else-if="report">
      <div class="rhdr">
        <div>
          <div class="reyebrow">AUDIT REPORT</div>
          <div class="ph">{{ report.summary.project_name }}</div>
          <div class="rmeta">
            Completed in {{ durationText }} ·
            {{ report.summary.is_dynamic ? 'eBPF Dynamic Verification Enabled' : 'Static Audit Only' }}
          </div>
        </div>
        <div class="racts">
          <button class="bp bg" :disabled="pdfExporting" @click="handleExportPdf">{{ pdfExporting ? '导出中…' : '↓ Export PDF' }}</button>
        </div>
      </div>

      <!-- Summary cards -->
      <div class="smgrid">
        <div class="smcard"><div class="smlbl">VULNERABILITIES</div><div class="smval" style="color:var(--rc)">{{ vulns.length }}</div><div class="smsub">{{ confirmedCount }} confirmed · {{ unverifiedCount }} unverified</div></div>
        <div class="smcard"><div class="smlbl">COMPONENT RISKS</div><div class="smval" style="color:var(--hi)">{{ components.length }}</div><div class="smsub">CVEs in dependencies</div></div>
        <div class="smcard"><div class="smlbl">eBPF EVENTS</div><div class="smval">{{ ebpfTotal }}</div><div class="smsub">Kernel-level evidence</div></div>
        <div class="smcard"><div class="smlbl">SCAN TIME</div><div class="smval">{{ scanSeconds }}<span style="font-size:20px;font-weight:300">s</span></div><div class="smsub">End-to-end pipeline</div></div>
      </div>

      <!-- Vulnerabilities -->
      <div class="rsec">
        <div class="rsech">
          <div class="rsectl">Vulnerabilities <span class="cbadge">{{ vulns.length }}</span></div>
          <div style="display:flex;gap:6px">
            <span class="dbadge b-ok" style="font-size:11px;padding:3px 10px">{{ confirmedCount }} Confirmed</span>
            <span class="dbadge b-un" style="font-size:11px;padding:3px 10px">{{ unverifiedCount }} Unverified</span>
          </div>
        </div>

        <div v-if="vulns.length === 0" class="empty">未发现源码漏洞</div>

        <div v-for="v in vulns" :key="v.id" class="vcard">
          <div class="vcardh" @click="toggle(v.id)">
            <span class="vtag">{{ vulnTag(v.vuln_type) }}</span>
            <span class="vtit">{{ vulnTitle(v) }}</span>
            <span class="vloc">{{ v.file_path || 'unknown' }}<template v-if="v.line_number"> : {{ v.line_number }}</template></span>
            <span class="dbadge" :class="verifyBadge(v.verify_status)" style="font-size:11px;padding:3px 10px;margin-left:8px">{{ verifyText(v.verify_status) }}</span>
            <span class="vchev" :class="{ open: opened.has(v.id) }">▾</span>
          </div>
          <div v-show="opened.has(v.id)" class="vbody">
            <!-- code -->
            <div v-if="v.code_context" class="cblock">
              <div v-for="(ln, i) in codeLines(v)" :key="i" class="cln" :class="{ hl: ln.hl }">
                <span class="cno">{{ ln.no }}</span><span class="ctx">{{ ln.text }}</span>
              </div>
            </div>
            <!-- trigger -->
            <div v-if="v.trigger_condition" class="vfield"><div class="vfl">触发条件</div><div class="vfv">{{ v.trigger_condition }}</div></div>
            <!-- ebpf -->
            <div v-if="v.ebpf_logs.length" class="ebpflog">
              <div class="ebh"><span class="ebtag">eBPF</span><span>Kernel event log · uprobe@malloc / uprobe@free</span></div>
              <div class="erow ehead"><span>TIMESTAMP (ns)</span><span>EVENT</span><span>FUNCTION</span><span>ADDRESS</span></div>
              <div v-for="(e, i) in v.ebpf_logs" :key="i" class="erow">
                <span class="ets">{{ e.timestamp }}</span>
                <span class="eev">{{ e.event_type }}</span>
                <span class="efn">{{ e.function_name || '—' }}</span>
                <span class="ead">{{ e.memory_addr || '—' }}</span>
              </div>
            </div>
            <!-- crash log -->
            <div v-if="v.crash_output" class="crashbox">
              <div class="ebh"><span class="ebtag" style="background:#c93b2a">AFL++</span><span>Crash log</span></div>
              <pre>{{ v.crash_output }}</pre>
            </div>
            <!-- fix -->
            <div v-if="v.fix_suggestion" class="advbox">
              <div class="advico">⚑</div>
              <div class="advtxt"><strong>Fix: </strong>{{ v.fix_suggestion }}</div>
            </div>
          </div>
        </div>
      </div>

      <!-- Component risk (SBOM) -->
      <div class="rsec">
        <div class="rsech"><div class="rsectl">Component Risk (SBOM) <span class="cbadge">{{ components.length }} CVEs</span></div></div>
        <div class="rtwrap">
          <table class="rtable">
            <thead><tr><th>Library</th><th>Version</th><th>CVE</th><th>CVSS</th><th>Severity</th><th>Description</th></tr></thead>
            <tbody>
              <tr v-if="components.length === 0"><td colspan="6" style="color:var(--fog)">未发现已知 CVE 风险</td></tr>
              <tr v-for="(c, i) in components" :key="i">
                <td class="mono strong">{{ c.library_name }}</td>
                <td class="mono soft">{{ c.version || 'unknown' }}</td>
                <td><a v-if="c.cve_id" class="cvea" :href="c.nvd_url || `https://nvd.nist.gov/vuln/detail/${c.cve_id}`" target="_blank">{{ c.cve_id }}</a><span v-else style="color:var(--fog)">—</span></td>
                <td><span class="cs" :class="cvssClass(c.cvss_score)">{{ c.cvss_score ?? '—' }}</span></td>
                <td><span class="dbadge" :class="'sev-' + c.severity">{{ c.severity }}</span></td>
                <td style="color:var(--grv)">{{ c.description || '—' }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </template>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { getTask, getTaskReport, exportPdf } from '@/api/tasks'
import { useTaskStore } from '@/stores/taskStore'
import type { AuditReport, Vulnerability } from '@/types/api'

const route = useRoute()
const router = useRouter()
const store = useTaskStore()
const taskId = route.params.id as string

const loading = ref(true)
const notReady = ref(false)
const report = ref<AuditReport | null>(null)
const pdfExporting = ref(false)
const opened = ref(new Set<string>())

const components = computed(() => report.value?.components ?? [])
const vulns = computed(() => report.value?.vulnerabilities ?? [])
const confirmedCount = computed(() => vulns.value.filter((v) => v.verify_status === 'confirmed').length)
const unverifiedCount = computed(() => vulns.value.filter((v) => v.verify_status !== 'confirmed').length)
const ebpfTotal = computed(() => vulns.value.reduce((s, v) => s + v.ebpf_logs.length, 0))
const scanSeconds = computed(() => {
  const t = report.value?.summary.total_time_seconds
  return t != null ? Math.round(t) : '—'
})
const durationText = computed(() => {
  const t = report.value?.summary.total_time_seconds
  if (t == null) return '—'
  return t < 60 ? `${t.toFixed(1)}s` : `${Math.floor(t / 60)}m ${Math.round(t % 60)}s`
})

function toggle(id: string) {
  if (opened.value.has(id)) opened.value.delete(id)
  else opened.value.add(id)
  opened.value = new Set(opened.value)
}

function vulnTag(t: string) {
  const m: Record<string, string> = {
    UAF: 'CWE-416 UAF', 'Use-After-Free': 'CWE-416 UAF',
    heap_overflow: 'CWE-122 HEAP', Heap_Overflow: 'CWE-122 HEAP',
    double_free: 'CWE-415 DBLF', Double_Free: 'CWE-415 DBLF',
    stack_overflow: 'CWE-121 STK'
  }
  return m[t] || t.toUpperCase()
}
function vulnTitle(v: Vulnerability) {
  const label: Record<string, string> = {
    UAF: 'Use-After-Free', 'Use-After-Free': 'Use-After-Free',
    heap_overflow: 'Heap Buffer Overflow', Heap_Overflow: 'Heap Buffer Overflow',
    double_free: 'Double Free', stack_overflow: 'Stack Overflow'
  }
  const base = label[v.vuln_type] || v.vuln_type
  return v.description ? `${base}` : base
}

// code_context 形如 "1232: free(buf);\n1234: memcpy(...)"
function codeLines(v: Vulnerability) {
  const raw = (v.code_context || '').split('\n').filter((l) => l.length > 0)
  return raw.map((line) => {
    const m = line.match(/^\s*(\d+)\s*:\s?(.*)$/)
    const no = m ? m[1] : ''
    const text = m ? m[2] : line
    const hl = v.line_number != null && no === String(v.line_number)
    return { no, text, hl }
  })
}

function verifyText(s: string) {
  return { confirmed: '● eBPF Confirmed', unverified: 'Unverified', false_positive: 'False Positive' }[s] || s
}
function verifyBadge(s: string) {
  if (s === 'confirmed') return 'b-ok'
  if (s === 'false_positive') return 'b-med'
  return 'b-un'
}
function cvssClass(score: number | null) {
  if (score == null) return ''
  if (score >= 7) return 'hi'
  if (score >= 4) return 'med'
  return 'lo'
}

async function handleExportPdf() {
  pdfExporting.value = true
  try {
    const resp = await exportPdf(taskId)
    const blob = new Blob([resp.data], { type: 'application/pdf' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `SENTINEL_Report_${report.value?.summary.project_name ?? taskId}.pdf`
    a.click()
    URL.revokeObjectURL(url)
  } catch { /* 拦截器已处理 */ } finally {
    pdfExporting.value = false
  }
}

function goMonitor() {
  router.push({ name: 'monitor', params: { id: taskId } })
}

onMounted(async () => {
  loading.value = true
  try {
    const t = await getTask(taskId)
    store.setCurrentTask(t.data.data)
    if (t.data.data.status !== 'completed') {
      notReady.value = true
      return
    }
    const r = await getTaskReport(taskId)
    report.value = r.data.data
    store.setCurrentReport(r.data.data)
    // 默认展开第一个 confirmed 漏洞
    const first = vulns.value.find((v) => v.verify_status === 'confirmed') || vulns.value[0]
    if (first) opened.value = new Set([first.id])
  } catch {
    notReady.value = true
  } finally {
    loading.value = false
  }
})
</script>

<style scoped>
.page-report { max-width: 1120px; margin: 0 auto; padding: 72px 44px; }
.rload { text-align: center; padding: 120px 24px; color: var(--grv); font-size: 14px; }
.rhdr { display: grid; grid-template-columns: 1fr auto; gap: 40px; align-items: start; margin-bottom: 44px; padding-bottom: 32px; border-bottom: 1px solid var(--ch); }
.reyebrow { font-size: 11px; font-weight: 700; letter-spacing: .6px; text-transform: uppercase; color: var(--w1); margin-bottom: 10px; }
.ph { font-family: var(--fd); font-size: 40px; letter-spacing: -.8px; line-height: 1.1; }
.rmeta { font-size: 13px; color: var(--grv); margin-top: 8px; }
.racts { display: flex; gap: 8px; }
.racts .bp { font-size: 12px; padding: 8px 16px; }
/* REP2 */
.smgrid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; margin-bottom: 44px; }
.smcard { background: #fff; border-radius: 16px; border: 1px solid var(--ch); box-shadow: var(--sc); padding: 20px 22px; position: relative; overflow: hidden; }
.smcard::before { content: ''; position: absolute; top: 0; left: 0; right: 0; height: 3px; background: linear-gradient(90deg, var(--w1), var(--amber)); }
.smlbl { font-size: 11px; color: var(--fog); font-weight: 600; margin-bottom: 8px; }
.smval { font-family: var(--fd); font-size: 38px; letter-spacing: -.8px; line-height: 1; }
.smsub { font-size: 11px; color: var(--grv); margin-top: 6px; }
.rsec { margin-bottom: 44px; }
.rsech { display: flex; align-items: center; justify-content: space-between; margin-bottom: 16px; }
.rsectl { font-size: 16px; font-weight: 600; display: flex; align-items: center; gap: 8px; }
.cbadge { font-size: 11px; font-weight: 500; padding: 2px 9px; border-radius: 9999px; background: var(--pw); color: var(--grv); border: 1px solid var(--ch); }
.empty { background: #fff; border: 1px solid var(--ch); border-radius: 16px; box-shadow: var(--sc); padding: 28px; text-align: center; color: var(--fog); font-size: 13px; }
/* REP3 */
.vcard { background: #fff; border-radius: 16px; border: 1px solid var(--ch); box-shadow: var(--sc); margin-bottom: 12px; overflow: hidden; transition: box-shadow .2s; }
.vcard:hover { box-shadow: 0 0 0 1px rgba(255, 107, 53, .2), 0 4px 20px rgba(255, 107, 53, .1); }
.vcardh { padding: 16px 20px; display: flex; align-items: center; gap: 12px; cursor: pointer; }
.vtag { font-family: var(--fm); font-size: 10px; padding: 4px 9px; border-radius: 5px; background: var(--obs); color: #fff; flex-shrink: 0; }
.vtit { font-size: 13px; font-weight: 600; flex: 1; }
.vloc { font-family: var(--fm); font-size: 11px; color: var(--fog); }
.vchev { color: var(--fog); font-size: 13px; transition: transform .2s; }
.vchev.open { transform: rotate(180deg); }
.vbody { padding: 0 20px 18px; }
.cblock { background: #f8f6f3; border: 1px solid var(--ch); border-radius: 10px; padding: 13px 16px; font-family: var(--fm); font-size: 12px; line-height: 1.75; margin-bottom: 12px; overflow-x: auto; }
.cln { display: flex; gap: 14px; }
.cno { color: var(--fog); min-width: 30px; text-align: right; }
.ctx { color: var(--obs); white-space: pre; }
.cln.hl { background: rgba(255, 107, 53, .1); margin: 0 -16px; padding: 0 16px; border-radius: 4px; }
.cln.hl .ctx { color: #9a3a1e; font-weight: 500; }
.vfield { margin-bottom: 12px; }
.vfl { font-size: 10px; font-weight: 700; letter-spacing: .5px; text-transform: uppercase; color: var(--fog); margin-bottom: 5px; }
.vfv { font-size: 12.5px; color: var(--grv); line-height: 1.65; }
/* REP4 */
.ebpflog { background: #141210; border-radius: 10px; padding: 13px 16px; margin-bottom: 12px; border: 1px solid #2a2520; }
.ebh { display: flex; align-items: center; gap: 8px; font-size: 11px; color: #665f55; margin-bottom: 10px; padding-bottom: 8px; border-bottom: 1px solid #221e19; }
.ebtag { font-size: 10px; font-weight: 700; padding: 2px 8px; border-radius: 4px; background: #7c3aed; color: #fff; }
.erow { display: grid; grid-template-columns: 1.2fr 1.1fr 1fr 1.4fr; gap: 6px; font-family: var(--fm); font-size: 11px; padding: 4px 0; border-bottom: 1px solid #1a1715; }
.erow:last-child { border-bottom: none; }
.erow.ehead { font-size: 10px; color: #3d3730; margin-bottom: 4px; }
.ets { color: #6b6359; }
.eev { color: #ef4444; }
.efn { color: #34d399; }
.ead { color: #c084fc; word-break: break-all; }
.crashbox { background: #141210; border-radius: 10px; padding: 13px 16px; margin-bottom: 12px; border: 1px solid #2a2520; }
.crashbox pre { font-family: var(--fm); font-size: 11px; color: #f59e0b; line-height: 1.6; white-space: pre-wrap; word-break: break-all; max-height: 220px; overflow-y: auto; }
.advbox { display: flex; gap: 10px; padding: 13px 15px; border-radius: 10px; background: linear-gradient(135deg, rgba(255, 107, 53, .06), rgba(247, 166, 80, .04)); border: 1px solid rgba(255, 107, 53, .2); }
.advico { font-size: 14px; flex-shrink: 0; margin-top: 1px; }
.advtxt { font-size: 12.5px; color: var(--grv); line-height: 1.6; }
.advtxt strong { color: var(--obs); }
/* REP5 */
.rtwrap { background: #fff; border-radius: 16px; border: 1px solid var(--ch); box-shadow: var(--sc); overflow: hidden; }
.rtable { width: 100%; border-collapse: collapse; }
.rtable th { text-align: left; padding: 10px 16px; font-size: 11px; font-weight: 700; color: var(--fog); letter-spacing: .4px; border-bottom: 1px solid var(--ch); }
.rtable td { padding: 12px 16px; border-bottom: 1px solid var(--ch); font-size: 13px; }
.rtable tr:last-child td { border-bottom: none; }
.rtable tr:hover td { background: var(--w4); }
.rtable .mono { font-family: var(--fm); font-size: 12px; }
.rtable .strong { font-weight: 600; }
.rtable .soft { color: var(--grv); }
.cvea { font-family: var(--fm); font-size: 11px; color: var(--blue); text-decoration: none; }
.cvea:hover { text-decoration: underline; }
.cs { font-family: var(--fm); font-size: 12px; }
.cs.hi { color: var(--rc); }
.cs.med { color: var(--hi); }
.cs.lo { color: var(--ok); }

@media (max-width: 900px) {
  .page-report { padding: 48px 18px; }
  .rhdr { grid-template-columns: 1fr; gap: 16px; }
  .smgrid { grid-template-columns: 1fr 1fr; }
}
</style>
