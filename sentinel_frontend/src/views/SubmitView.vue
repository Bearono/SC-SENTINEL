<template>
  <div class="page-submit">
    <div class="submit-layout">
      <!-- LEFT CONTEXT PANEL -->
      <div class="submit-side">
        <div class="ctx-panel" :class="{ show: leftPanel }">
          <div class="cphead"><span class="cptag">{{ leftPanel?.tag }}</span><span class="cptit">{{ leftPanel?.title }}</span></div>
          <div class="cpbody">
            <div class="cp-kv"><span class="cp-k">Severity</span><span class="cp-v">{{ leftPanel?.severity }}</span></div>
            <div class="cp-bar-wrap"><div class="cp-bar-fill" :style="{ width: (leftPanel?.bar || 0) + '%' }" /></div>
            <div class="cp-desc">{{ leftPanel?.desc }}</div>
            <div class="cp-example"><strong>{{ leftPanel?.exTitle }}</strong>{{ leftPanel?.exText }}</div>
          </div>
        </div>
      </div>

      <!-- MAIN FORM -->
      <div class="submit-main">
        <div class="ph">New Audit</div>
        <p class="psub">上传 C/C++ 项目，配置扫描策略，启动 Multi-Agent 审计流水线</p>
        <div class="fcard">
          <!-- Source -->
          <div class="fsec">
            <div class="fstit">Source</div>
            <div class="srctabs">
              <button class="stab" :class="{ active: srcType === 'zip' }" @click="srcType = 'zip'">ZIP Upload</button>
              <button class="stab" :class="{ active: srcType === 'github' }" @click="srcType = 'github'">GitHub URL</button>
            </div>
            <div v-if="srcType === 'zip'">
              <input ref="fileInput" type="file" accept=".zip,.tar.gz,.tgz" style="display:none" @change="onFileSelect" />
              <div class="uzone" :class="{ filled: file }" @click="fileInput?.click()" @dragover.prevent @drop.prevent="onDrop">
                <div class="uico">
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4M17 8l-5-5-5 5M12 3v12" /></svg>
                </div>
                <div class="utit">{{ file ? file.name : 'Drop your project .zip here' }}</div>
                <div class="uhint">{{ file ? formatSize(file.size) + ' · 点击可重新选择' : '点击选择文件 · 最大 100MB · zip / tar.gz' }}</div>
              </div>
            </div>
            <div v-else>
              <div class="fr"><label class="fl">GitHub Repository URL</label><input v-model="githubUrl" class="fi" type="text" placeholder="https://github.com/user/repo" /></div>
            </div>
          </div>

          <!-- Project Info -->
          <div class="fsec">
            <div class="fstit">Project Info</div>
            <div class="fr"><label class="fl">Project Name</label><input v-model="projectName" class="fi" type="text" placeholder="e.g. libpng-vuln-demo" /></div>
          </div>

          <!-- Vulnerability Targets -->
          <div class="fsec">
            <div class="fstit">Vulnerability Targets</div>
            <div class="vchecks">
              <div
                v-for="cwe in cweList"
                :key="cwe.code"
                class="vcheck"
                :class="{ sel: selected.has(cwe.code) }"
                @click="toggleCwe(cwe.code)"
                @mouseenter="leftPanel = cwe.panel"
                @mouseleave="leftPanel = null"
              >{{ cwe.label }}</div>
            </div>
          </div>

          <!-- Options -->
          <div class="fsec">
            <div class="fstit">Analysis Options</div>
            <div class="trow">
              <div><div class="tn">eBPF Dynamic Verification</div><div class="td">启动 Docker 沙箱，AFL++ + eBPF 内核级确认漏洞（推荐）</div></div>
              <div class="tog" :class="{ on: isDynamic }" @click="isDynamic = !isDynamic"><div class="tthumb" /></div>
            </div>
            <div class="trow">
              <div><div class="tn">Generate PDF Report</div><div class="td">任务完成后可在报告页一键导出审计 PDF</div></div>
              <div class="tog on"><div class="tthumb" /></div>
            </div>
          </div>

          <div class="sfoot">
            <span class="sfnote">{{ errorMsg || '任务在隔离沙箱中运行 · 完成后自动清理' }}</span>
            <button class="bsub" :disabled="!canSubmit || submitting" @click="handleSubmit">
              {{ submitting ? 'Launching…' : 'Launch Audit →' }}
            </button>
          </div>
        </div>
      </div>

      <!-- RIGHT CONTEXT PANEL -->
      <div class="submit-side right">
        <div class="ctx-panel right-panel" :class="{ show: rightPanel }">
          <div class="cphead"><span class="cptag">{{ rightPanel?.tag }}</span><span class="cptit">{{ rightPanel?.title }}</span></div>
          <div class="cpbody"><div class="cp-desc">{{ rightPanel?.body }}</div></div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue'
import { useRouter } from 'vue-router'
import { submitTask } from '@/api/tasks'
import { submitAudit } from '@/api/audit'
import { useTaskStore } from '@/stores/taskStore'

const router = useRouter()
const store = useTaskStore()

const srcType = ref<'zip' | 'github'>('zip')
const file = ref<File | null>(null)
const fileInput = ref<HTMLInputElement | null>(null)
const githubUrl = ref('')
const projectName = ref('')
const isDynamic = ref(true)
const submitting = ref(false)
const errorMsg = ref('')

// 目标漏洞类型映射到对接规范的标准缩写
const cweList = [
  { code: 'UAF', label: 'CWE-416 Use-After-Free', panel: { tag: 'UAF', title: 'Use-After-Free', severity: 'Critical', bar: 88, desc: '释放内存后继续使用已释放的指针，可能导致远程代码执行。CVSS 常达 9.0+。', exTitle: '经典案例', exText: 'CVE-2021-1782 · iOS Kernel UAF — 触发内核对象释放后重用，实现本地提权至 root。' } },
  { code: 'heap_overflow', label: 'CWE-122 Heap Overflow', panel: { tag: 'HEAP', title: 'Heap Overflow', severity: 'Critical', bar: 76, desc: '堆上的缓冲区写入超出分配边界，覆盖相邻内存结构，常被用于 tcache/fastbin 攻击。', exTitle: '经典案例', exText: 'CVE-2022-37434 · zlib — 超大 gzip header 触发堆溢出，CVSS 9.8。' } },
  { code: 'double_free', label: 'CWE-415 Double Free', panel: { tag: 'DBLF', title: 'Double Free', severity: 'High', bar: 65, desc: '同一指针被 free() 调用两次，破坏堆分配器元数据，可被利用为任意写原语。', exTitle: '检测方式', exText: 'eBPF uprobe 挂载 free()，记录每次释放地址 → 发现重复 free 同一地址时告警。' } },
  { code: 'stack_overflow', label: 'CWE-121 Stack Overflow', panel: { tag: 'STK', title: 'Stack Overflow', severity: 'High', bar: 54, desc: '栈上缓冲区超出边界，覆盖返回地址或 canary，通常通过 ROP 链实现代码执行。', exTitle: '防御建议', exText: '编译时启用 -fstack-protector-strong 和 ASLR；避免使用 gets()、scanf()。' } }
]

const selected = ref(new Set<string>(['UAF', 'heap_overflow', 'double_free']))
const leftPanel = ref<(typeof cweList)[number]['panel'] | null>(null)
const rightPanel = ref<{ tag: string; title: string; body: string } | null>(null)

function toggleCwe(code: string) {
  if (selected.value.has(code)) selected.value.delete(code)
  else selected.value.add(code)
  selected.value = new Set(selected.value)
}

const canSubmit = computed(() => {
  const hasSource = srcType.value === 'zip' ? !!file.value : githubUrl.value.trim() !== ''
  return hasSource && projectName.value.trim() !== ''
})

function onFileSelect(e: Event) {
  const f = (e.target as HTMLInputElement).files?.[0]
  if (f) setFile(f)
}
function onDrop(e: DragEvent) {
  const f = e.dataTransfer?.files?.[0]
  if (f) setFile(f)
}
function setFile(f: File) {
  file.value = f
  if (!projectName.value) projectName.value = f.name.replace(/\.(zip|tar\.gz|tgz)$/i, '')
}
function formatSize(b: number) {
  if (b < 1024) return `${b} B`
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`
  return `${(b / 1024 / 1024).toFixed(1)} MB`
}

async function handleSubmit() {
  if (!canSubmit.value || submitting.value) return
  errorMsg.value = ''
  submitting.value = true
  try {
    const fd = new FormData()
    fd.append('project_name', projectName.value.trim())
    fd.append('source_type', srcType.value)
    fd.append('is_dynamic', String(isDynamic.value))
    fd.append('target_vulns', JSON.stringify([...selected.value]))
    if (srcType.value === 'zip' && file.value) {
      fd.append('file', file.value)
    } else {
      fd.append('source_path', githubUrl.value.trim())
    }

    // 1) 创建任务
    const created = await submitTask(fd)
    const taskId = created.data.data.id

    // 2) 触发审计 Pipeline
    await submitAudit(taskId)

    // 3) 进入实时监控页
    store.resetProgress()
    router.push({ name: 'monitor', params: { id: taskId } })
  } catch (e) {
    errorMsg.value = e instanceof Error ? e.message : '提交失败，请检查后端服务'
    submitting.value = false
  }
}
</script>

<style scoped>
.page-submit { min-height: calc(100vh - 58px); position: relative; }
.submit-layout { display: grid; grid-template-columns: 1fr 560px 1fr; min-height: calc(100vh - 58px); max-width: 1400px; margin: 0 auto; padding: 0 24px; align-items: start; }
.submit-side { padding: 72px 16px 72px 32px; position: sticky; top: 58px; height: calc(100vh - 58px); display: flex; flex-direction: column; overflow: hidden; }
.submit-side.right { padding: 72px 32px 72px 16px; }
.submit-main { padding: 72px 32px; }
/* SUB2 */
.ctx-panel { background: #fff; border-radius: 18px; border: 1px solid var(--ch); box-shadow: var(--sf); overflow: hidden; opacity: 0; transform: translateX(-16px); transition: opacity .4s cubic-bezier(.22, 1, .36, 1), transform .4s cubic-bezier(.22, 1, .36, 1); pointer-events: none; }
.ctx-panel.show { opacity: 1; transform: translateX(0); pointer-events: auto; }
.ctx-panel.right-panel { transform: translateX(16px); }
.ctx-panel.right-panel.show { transform: translateX(0); }
.cphead { padding: 14px 18px; border-bottom: 1px solid var(--ch); display: flex; align-items: center; gap: 8px; }
.cptag { font-size: 10px; font-weight: 700; letter-spacing: .5px; text-transform: uppercase; padding: 2px 8px; border-radius: 9999px; background: linear-gradient(135deg, var(--w1), var(--amber)); color: #fff; }
.cptit { font-size: 13px; font-weight: 600; }
.cpbody { padding: 16px 18px; }
.cp-kv { display: flex; justify-content: space-between; align-items: baseline; margin-bottom: 8px; font-size: 12.5px; }
.cp-k { color: var(--grv); }
.cp-v { font-weight: 600; font-family: var(--fm); font-size: 11px; color: var(--obs); }
.cp-bar-wrap { height: 4px; background: var(--ch); border-radius: 9999px; overflow: hidden; margin-bottom: 12px; }
.cp-bar-fill { height: 100%; border-radius: 9999px; background: linear-gradient(90deg, var(--w1), var(--amber)); }
.cp-desc { font-size: 12.5px; color: var(--grv); line-height: 1.6; margin-bottom: 10px; }
.cp-example { background: var(--w4); border-radius: 8px; padding: 10px 12px; font-size: 12px; border-left: 3px solid var(--w1); }
.cp-example strong { display: block; font-size: 11px; font-weight: 700; letter-spacing: .4px; text-transform: uppercase; color: var(--w1); margin-bottom: 4px; }
/* SUB3 */
.ph { font-family: var(--fd); font-size: 40px; letter-spacing: -.8px; line-height: 1.1; margin-bottom: 8px; }
.psub { font-size: 15px; color: var(--grv); margin-bottom: 40px; }
.fcard { background: #fff; border-radius: 22px; border: 1px solid var(--ch); box-shadow: var(--sc); overflow: hidden; }
.fsec { padding: 26px 30px; border-bottom: 1px solid var(--ch); }
.fsec:last-child { border-bottom: none; }
.fstit { font-size: 11px; font-weight: 700; letter-spacing: .6px; text-transform: uppercase; color: var(--fog); margin-bottom: 16px; }
.srctabs { display: flex; gap: 6px; margin-bottom: 18px; }
.stab { padding: 7px 16px; border-radius: 9999px; border: 1px solid var(--ch); font-size: 13px; font-weight: 500; cursor: pointer; background: #fff; color: var(--grv); transition: all .15s; font-family: var(--fb); }
.stab.active { background: var(--obs); color: #fff; border-color: var(--obs); }
.uzone { border: 1.5px dashed var(--ch); border-radius: 14px; padding: 40px 24px; text-align: center; cursor: pointer; transition: all .22s; background: var(--pw); }
.uzone:hover { border-color: var(--w1); }
.uzone.filled { border-color: var(--ok); border-style: solid; background: var(--obg); }
.uico { width: 44px; height: 44px; background: #fff; border: 1px solid var(--ch); border-radius: 10px; margin: 0 auto 12px; display: flex; align-items: center; justify-content: center; box-shadow: var(--sf); }
.utit { font-size: 14px; font-weight: 500; margin-bottom: 4px; }
.uhint { font-size: 12px; color: var(--fog); }
.fl { font-size: 13px; font-weight: 500; margin-bottom: 8px; display: block; }
.fi { width: 100%; padding: 10px 14px; border-radius: 9px; border: 1px solid var(--ch); background: #fff; font-family: var(--fb); font-size: 13px; color: var(--obs); outline: none; transition: border .15s; }
.fi:focus { border-color: var(--w1); }
.fi::placeholder { color: var(--fog); }
.fr { margin-bottom: 14px; }
.fr:last-child { margin-bottom: 0; }
/* SUB4 */
.vchecks { display: flex; flex-wrap: wrap; gap: 8px; }
.vcheck { display: flex; align-items: center; gap: 7px; padding: 7px 15px; border-radius: 9999px; border: 1px solid var(--ch); font-size: 12px; font-weight: 500; cursor: pointer; background: #fff; color: var(--grv); transition: all .2s; user-select: none; font-family: var(--fb); }
.vcheck:hover { border-color: rgba(255, 107, 53, .4); background: var(--w4); }
.vcheck.sel { background: linear-gradient(135deg, var(--w1), var(--amber)); color: #fff; border-color: transparent; box-shadow: 0 2px 8px rgba(255, 107, 53, .3); }
.trow { display: flex; align-items: center; justify-content: space-between; padding: 13px 0; border-bottom: 1px solid var(--ch); }
.trow:last-child { border-bottom: none; }
.tn { font-size: 13px; font-weight: 500; }
.td { font-size: 12px; color: var(--grv); margin-top: 2px; }
.tog { width: 40px; height: 22px; border-radius: 11px; border: 1px solid var(--ch); background: var(--ch); cursor: pointer; position: relative; transition: all .2s; flex-shrink: 0; }
.tog.on { background: linear-gradient(135deg, var(--w1), var(--amber)); border-color: var(--w1); }
.tthumb { width: 16px; height: 16px; border-radius: 50%; background: #fff; position: absolute; top: 2px; left: 2px; transition: transform .2s; box-shadow: 0 1px 3px rgba(0, 0, 0, .2); }
.tog.on .tthumb { transform: translateX(18px); }
.sfoot { padding: 20px 30px; background: var(--pw); border-top: 1px solid var(--ch); display: flex; align-items: center; justify-content: space-between; gap: 16px; }
.sfnote { font-size: 12px; color: var(--fog); }
.bsub { padding: 11px 28px; border-radius: 9999px; background: linear-gradient(135deg, var(--w1), var(--amber)); color: #fff; border: none; font-family: var(--fb); font-size: 13px; font-weight: 600; cursor: pointer; box-shadow: 0 4px 16px rgba(255, 107, 53, .35); transition: all .15s; white-space: nowrap; }
.bsub:hover:not(:disabled) { box-shadow: 0 6px 22px rgba(255, 107, 53, .48); transform: translateY(-1px); }
.bsub:disabled { opacity: .5; cursor: not-allowed; }

@media (max-width: 1100px) {
  .submit-layout { grid-template-columns: 1fr; }
  .submit-side { display: none; }
  .submit-main { padding: 48px 0; }
}
</style>
