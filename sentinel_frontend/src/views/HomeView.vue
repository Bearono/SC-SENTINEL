<template>
  <div class="home-page">
    <!-- Hero 区域 -->
    <section class="hero-section">
      <div class="container">
        <div class="hero-badge">
          <span class="badge badge--running">✦ CISCN 2025</span>
        </div>
        <h1 class="hero-title">
          面向 C/C++ 开源供应链的<br />
          <span class="title-accent">智能漏洞审计</span>系统
        </h1>
        <p class="hero-subtitle">
          基于 eBPF 内核级探针 + LLM 语义分析，深度挖掘供应链组件中的
          UAF、堆溢出、Double Free 等内存安全漏洞
        </p>
        <div class="hero-actions">
          <el-button
            type="primary"
            size="large"
            class="btn-start"
            @click="scrollToUpload"
          >
            <el-icon><Upload /></el-icon>
            开始审计
          </el-button>
          <el-button
            size="large"
            class="btn-demo"
            plain
            @click="fillHeartbleedDemo"
          >
            <el-icon><View /></el-icon>
            查看 Demo (Heartbleed)
          </el-button>
        </div>
      </div>
    </section>

    <!-- 底部统计数字卡片 -->
    <section class="stats-section">
      <div class="container">
        <div class="stats-grid">
          <div v-for="stat in stats" :key="stat.label" class="stat-card sentinel-card">
            <div class="stat-value count-up">{{ stat.value }}</div>
            <div class="stat-label">{{ stat.label }}</div>
          </div>
        </div>
      </div>
    </section>

    <!-- 上传区域 -->
    <section id="upload-section" class="upload-section">
      <div class="container">
        <div class="section-header">
          <h2 class="section-title">提交审计项目</h2>
          <p class="section-desc">上传 C/C++ 源码压缩包，系统将自动进行 SBOM 分析、LLM 语义审计与动态 Fuzzing 验证</p>
        </div>

        <div class="upload-layout">
          <!-- 左：上传框 -->
          <div class="upload-panel sentinel-card">
            <h3 class="panel-title">源码上传</h3>

            <!-- 拖拽上传区 -->
            <div
              class="drop-zone"
              :class="{ 'drop-zone--active': isDragging, 'drop-zone--filled': uploadedFile }"
              @dragover.prevent="isDragging = true"
              @dragleave.prevent="isDragging = false"
              @drop.prevent="onDrop"
              @click="triggerFileInput"
            >
              <input
                ref="fileInputRef"
                type="file"
                accept=".zip"
                style="display: none"
                @change="onFileSelect"
              />
              <template v-if="!uploadedFile">
                <el-icon class="drop-icon"><FolderAdd /></el-icon>
                <p class="drop-text">拖拽 <strong>.zip</strong> 文件到此处，或点击选择</p>
                <p class="drop-hint">仅支持 .zip 格式，建议 &lt; 50MB</p>
              </template>
              <template v-else>
                <el-icon class="drop-icon drop-icon--filled"><DocumentChecked /></el-icon>
                <p class="drop-text file-name">{{ uploadedFile.name }}</p>
                <p class="drop-hint">{{ formatFileSize(uploadedFile.size) }}</p>
                <el-button
                  size="small"
                  type="danger"
                  plain
                  class="remove-file-btn"
                  @click.stop="uploadedFile = null"
                >移除</el-button>
              </template>
            </div>

            <!-- 分隔线 -->
            <div class="divider"><span>或填写 GitHub 仓库地址</span></div>

            <!-- GitHub URL 输入框 -->
            <el-input
              v-model="form.github_url"
              placeholder="https://github.com/username/repo"
              :prefix-icon="Link"
              clearable
              size="large"
            />
          </div>

          <!-- 右：审计选项 -->
          <div class="options-panel sentinel-card">
            <h3 class="panel-title">审计选项</h3>

            <!-- 项目名称 -->
            <div class="form-item">
              <label class="form-label">项目名称 <span class="required">*</span></label>
              <el-input
                v-model="form.project_name"
                placeholder="例如：openssl-1.0.1e"
                size="large"
                clearable
              />
            </div>

            <!-- 启用动态验证 -->
            <div class="form-item">
              <div class="switch-row">
                <div>
                  <div class="form-label">启用动态验证（eBPF + AFL++）</div>
                  <div class="form-desc">勾选后将在隔离 Docker 沙箱中进行 Fuzzing 测试</div>
                </div>
                <el-switch
                  v-model="form.is_dynamic"
                  active-color="var(--sentinel-warning)"
                  inactive-color="var(--border-normal)"
                />
              </div>
              <Transition name="el-fade-in">
                <div v-if="form.is_dynamic" class="time-estimate">
                  <el-icon><Timer /></el-icon>
                  预计额外增加 <strong>约 5 分钟</strong>（沙箱 Fuzzing 时间）
                </div>
              </Transition>
            </div>

            <!-- 目标漏洞类型 -->
            <div class="form-item">
              <label class="form-label">目标漏洞类型</label>
              <el-checkbox-group v-model="form.vuln_types" class="vuln-checkboxes">
                <el-checkbox value="uaf">Use-After-Free (UAF)</el-checkbox>
                <el-checkbox value="heap_overflow">堆溢出 (Heap Overflow)</el-checkbox>
                <el-checkbox value="double_free">Double Free</el-checkbox>
                <el-checkbox value="stack_overflow">栈溢出 (Stack Overflow)</el-checkbox>
              </el-checkbox-group>
            </div>

            <!-- 提交按钮 -->
            <el-button
              type="primary"
              size="large"
              class="submit-btn"
              :loading="submitting"
              :disabled="!canSubmit"
              @click="handleSubmit"
            >
              <el-icon v-if="!submitting"><Promotion /></el-icon>
              {{ submitting ? '提交中...' : '开始审计' }}
            </el-button>
          </div>
        </div>
      </div>
    </section>
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Upload, View, FolderAdd, DocumentChecked, Link, Timer, Promotion } from '@element-plus/icons-vue'
import { submitTask } from '@/api/tasks'

const router = useRouter()

// ── 统计数字（静态展示数据，可替换为接口数据） ─────────────────
const stats = [
  { value: '142',    label: '已审计项目数' },
  { value: '1,038',  label: '发现漏洞总数' },
  { value: '8.3 min', label: '平均审计时长' }
]

// ── 表单状态 ────────────────────────────────────────────────────
const fileInputRef = ref<HTMLInputElement | null>(null)
const uploadedFile = ref<File | null>(null)
const isDragging = ref(false)
const submitting = ref(false)

const form = ref({
  project_name: '',
  github_url: '',
  is_dynamic: false,
  vuln_types: ['uaf', 'heap_overflow', 'double_free', 'stack_overflow'] as string[]
})

const canSubmit = computed(() => {
  const hasSource = uploadedFile.value !== null || form.value.github_url.trim() !== ''
  return hasSource && form.value.project_name.trim() !== ''
})

// ── 文件上传逻辑 ─────────────────────────────────────────────────
function triggerFileInput() {
  if (!uploadedFile.value) fileInputRef.value?.click()
}

function onFileSelect(e: Event) {
  const input = e.target as HTMLInputElement
  const file = input.files?.[0]
  if (file) validateAndSetFile(file)
}

function onDrop(e: DragEvent) {
  isDragging.value = false
  const file = e.dataTransfer?.files[0]
  if (file) validateAndSetFile(file)
}

function validateAndSetFile(file: File) {
  if (!file.name.endsWith('.zip')) {
    ElMessage.error('仅支持 .zip 格式文件')
    return
  }
  if (file.size > 100 * 1024 * 1024) {
    ElMessage.warning('文件大小建议不超过 100MB')
  }
  uploadedFile.value = file
  if (!form.value.project_name) {
    // 自动填充项目名
    form.value.project_name = file.name.replace(/\.zip$/, '')
  }
}

function formatFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

// ── Heartbleed Demo 预填 ─────────────────────────────────────────
function fillHeartbleedDemo() {
  form.value.project_name = 'OpenSSL-1.0.1e-Heartbleed'
  form.value.github_url = 'https://github.com/openssl/openssl'
  form.value.is_dynamic = true
  form.value.vuln_types = ['uaf', 'heap_overflow']
  ElMessage.info('已预填 Heartbleed 演示数据')
  scrollToUpload()
}

// ── 提交 ─────────────────────────────────────────────────────────
async function handleSubmit() {
  if (!canSubmit.value) return

  try {
    await ElMessageBox.confirm(
      `确认提交项目「${form.value.project_name}」进行审计？${form.value.is_dynamic ? '（已启用动态验证，预计约 5 分钟）' : ''}`,
      '确认提交',
      { confirmButtonText: '确认', cancelButtonText: '取消', type: 'info' }
    )
  } catch {
    return // 用户取消
  }

  submitting.value = true
  try {
    const fd = new FormData()
    fd.append('project_name', form.value.project_name.trim())
    fd.append('is_dynamic', String(form.value.is_dynamic))
    fd.append('vuln_types', form.value.vuln_types.join(','))

    if (uploadedFile.value) {
      fd.append('file', uploadedFile.value)
      fd.append('source_type', 'zip')
    } else {
      fd.append('github_url', form.value.github_url.trim())
      fd.append('source_type', 'github')
    }

    const resp = await submitTask(fd)
    const taskId = resp.data.data.id

    ElMessage.success('任务已提交，正在跳转到审计详情页...')
    router.push({ name: 'report', params: { id: taskId } })
  } finally {
    submitting.value = false
  }
}

function scrollToUpload() {
  document.getElementById('upload-section')?.scrollIntoView({ behavior: 'smooth' })
}
</script>

<style scoped>
.home-page { min-height: 100vh; }

/* ── Hero ── */
.hero-section {
  padding: 80px 0 60px;
  background: linear-gradient(180deg, #0d1821 0%, #112233 100%);
  border-bottom: 1px solid var(--border-subtle);
}
.container {
  max-width: 1100px;
  margin: 0 auto;
  padding: 0 24px;
}
.hero-badge { margin-bottom: 20px; }
.hero-title {
  font-size: 44px;
  font-weight: 700;
  line-height: 1.25;
  color: var(--text-primary);
  margin-bottom: 20px;
}
.title-accent { color: var(--sentinel-warning); }
.hero-subtitle {
  font-size: 16px;
  color: var(--text-secondary);
  max-width: 600px;
  margin-bottom: 36px;
  line-height: 1.8;
}
.hero-actions { display: flex; gap: 12px; flex-wrap: wrap; }
.btn-start {
  background: var(--sentinel-primary-light);
  border-color: var(--sentinel-primary-light);
  font-size: 15px;
  padding: 12px 28px;
}
.btn-demo {
  border-color: var(--border-normal);
  color: var(--text-secondary);
  font-size: 15px;
  padding: 12px 28px;
}
.btn-demo:hover { border-color: var(--sentinel-warning); color: var(--sentinel-warning); }

/* ── 统计 ── */
.stats-section { padding: 32px 0; }
.stats-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; }
.stat-card {
  padding: 24px 28px;
  text-align: center;
  transition: transform var(--transition-normal);
}
.stat-card:hover { transform: translateY(-2px); }
.stat-value { font-size: 32px; font-weight: 700; color: var(--sentinel-warning); margin-bottom: 4px; }
.stat-label { font-size: 13px; color: var(--text-secondary); }

/* ── 上传区 ── */
.upload-section { padding: 60px 0 80px; }
.section-header { margin-bottom: 40px; text-align: center; }
.section-title { font-size: 28px; font-weight: 700; color: var(--text-primary); margin-bottom: 8px; }
.section-desc { font-size: 14px; color: var(--text-secondary); }
.upload-layout { display: grid; grid-template-columns: 1fr 1fr; gap: 24px; }

.upload-panel, .options-panel {
  padding: 28px;
  display: flex;
  flex-direction: column;
  gap: 20px;
}
.panel-title { font-size: 16px; font-weight: 600; color: var(--text-primary); margin-bottom: 4px; }

/* 拖拽区 */
.drop-zone {
  border: 2px dashed var(--border-normal);
  border-radius: var(--radius-lg);
  padding: 40px 20px;
  text-align: center;
  cursor: pointer;
  transition: border-color var(--transition-fast), background var(--transition-fast);
  background: transparent;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 8px;
}
.drop-zone:hover, .drop-zone--active {
  border-color: var(--sentinel-primary-light);
  background: rgba(30, 74, 120, 0.08);
}
.drop-zone--filled {
  border-color: var(--sentinel-success);
  border-style: solid;
  background: rgba(29, 158, 117, 0.06);
}
.drop-icon { font-size: 36px; color: var(--text-muted); }
.drop-icon--filled { color: var(--sentinel-success-light); }
.drop-text { font-size: 14px; color: var(--text-secondary); }
.drop-text strong { color: var(--text-primary); }
.drop-hint { font-size: 12px; color: var(--text-muted); }
.file-name { color: var(--sentinel-success-light) !important; font-weight: 500; }
.remove-file-btn { margin-top: 4px; }

/* 分隔线 */
.divider {
  display: flex;
  align-items: center;
  gap: 12px;
  color: var(--text-muted);
  font-size: 12px;
}
.divider::before, .divider::after {
  content: '';
  flex: 1;
  border-top: 1px solid var(--border-subtle);
}

/* 表单 */
.form-item { display: flex; flex-direction: column; gap: 8px; }
.form-label { font-size: 13px; font-weight: 500; color: var(--text-secondary); }
.form-desc  { font-size: 12px; color: var(--text-muted); margin-top: 2px; }
.required   { color: var(--sentinel-danger); }
.switch-row { display: flex; align-items: flex-start; justify-content: space-between; gap: 16px; }
.time-estimate {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 12px;
  color: var(--sentinel-warning);
  background: rgba(239, 159, 39, 0.1);
  border: 1px solid rgba(239, 159, 39, 0.2);
  border-radius: var(--radius-sm);
  padding: 6px 10px;
}
.time-estimate strong { color: var(--sentinel-warning); }
.vuln-checkboxes { display: flex; flex-direction: column; gap: 8px; }
.vuln-checkboxes :deep(.el-checkbox__label) { color: var(--text-secondary); font-size: 13px; }
.submit-btn { width: 100%; margin-top: auto; font-size: 15px; height: 48px; }

@media (max-width: 768px) {
  .hero-title { font-size: 28px; }
  .stats-grid { grid-template-columns: 1fr; }
  .upload-layout { grid-template-columns: 1fr; }
}
</style>
