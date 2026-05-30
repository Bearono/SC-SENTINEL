<template>
  <div class="about-page">
    <div class="container">

      <!-- 系统介绍 -->
      <section class="about-section">
        <div class="about-hero sentinel-card">
          <div class="hero-icon">⬡</div>
          <h1 class="hero-title">SENTINEL</h1>
          <p class="hero-desc">
            面向 C/C++ 开源供应链的 eBPF-LLM 协同漏洞审计与安全管理系统
          </p>
          <div class="divider-line" />
          <p class="intro-text">
            SENTINEL 针对 C/C++ 生态开源组件的供应链安全问题，结合大语言模型（LLM）的代码语义理解能力
            与 eBPF 内核级动态追踪技术，实现了从静态分析到动态验证的完整漏洞审计闭环。
            系统能够自动识别 UAF、堆溢出、Double Free、栈溢出等内存安全漏洞，
            并通过 AFL++ Fuzzing 对疑似漏洞进行动态验证，大幅降低误报率。
          </p>
        </div>
      </section>

      <!-- 技术架构图（文字描述版） -->
      <section class="about-section">
        <h2 class="section-heading">技术架构</h2>
        <div class="arch-grid">
          <div class="arch-card sentinel-card">
            <div class="arch-icon" style="color: var(--sentinel-primary-light);">
              <el-icon size="32"><Upload /></el-icon>
            </div>
            <div class="arch-label">输入层</div>
            <div class="arch-desc">ZIP 源码包 / GitHub 仓库，ZIP 解压与依赖文件提取</div>
          </div>
          <div class="arch-arrow">→</div>
          <div class="arch-card sentinel-card">
            <div class="arch-icon" style="color: var(--sentinel-warning);">
              <el-icon size="32"><Search /></el-icon>
            </div>
            <div class="arch-label">Agent A (ML)</div>
            <div class="arch-desc">SBOM 依赖分析，NVD/OSV 数据库 CVE 查询</div>
          </div>
          <div class="arch-arrow">→</div>
          <div class="arch-card sentinel-card">
            <div class="arch-icon" style="color: var(--sentinel-success-light);">
              <el-icon size="32"><DataAnalysis /></el-icon>
            </div>
            <div class="arch-label">Agent B (ML)</div>
            <div class="arch-desc">LLM 源码语义审计，漏洞定位与修复建议生成</div>
          </div>
          <div class="arch-arrow">→</div>
          <div class="arch-card sentinel-card">
            <div class="arch-icon" style="color: var(--sentinel-danger);">
              <el-icon size="32"><Monitor /></el-icon>
            </div>
            <div class="arch-label">动态验证层</div>
            <div class="arch-desc">Docker 隔离沙箱，AFL++ Fuzzing + eBPF uprobe 内核追踪</div>
          </div>
        </div>
      </section>

      <!-- 技术栈展示 -->
      <section class="about-section">
        <h2 class="section-heading">技术栈</h2>
        <div class="tech-grid">
          <div
            v-for="tech in techStack"
            :key="tech.name"
            class="tech-item sentinel-card"
          >
            <div class="tech-icon">{{ tech.icon }}</div>
            <div class="tech-name">{{ tech.name }}</div>
            <div class="tech-role">{{ tech.role }}</div>
          </div>
        </div>
      </section>

      <!-- 团队信息 -->
      <section class="about-section">
        <h2 class="section-heading">团队信息</h2>
        <div class="team-card sentinel-card">
          <div class="team-row">
            <div class="team-item">
              <div class="team-label">团队名称</div>
              <div class="team-value"><!-- 待填写 --></div>
            </div>
            <div class="team-item">
              <div class="team-label">所属学校</div>
              <div class="team-value"><!-- 待填写 --></div>
            </div>
            <div class="team-item">
              <div class="team-label">赛事</div>
              <div class="team-value">CISCN 2025</div>
            </div>
          </div>
          <div class="github-link" v-if="false">
            <!-- 开源后取消 v-if -->
            <el-button :icon="Link" plain>
              GitHub 仓库
            </el-button>
          </div>
        </div>
      </section>

    </div>
  </div>
</template>

<script setup lang="ts">
import { Upload, Search, DataAnalysis, Monitor, Link } from '@element-plus/icons-vue'

const techStack = [
  { icon: '🐍', name: 'Python',   role: '后端语言' },
  { icon: '⚡', name: 'FastAPI',  role: 'Web 框架' },
  { icon: '💚', name: 'Vue 3',    role: '前端框架' },
  { icon: '🐳', name: 'Docker',   role: '沙箱隔离' },
  { icon: '🔬', name: 'eBPF',     role: '内核级动态追踪' },
  { icon: '🔀', name: 'AFL++',    role: '模糊测试引擎' },
  { icon: '🤖', name: 'LLM API', role: '代码语义审计' },
  { icon: '🐘', name: 'PostgreSQL', role: '数据持久化' },
  { icon: '⚡', name: 'Redis',    role: '消息队列/缓存' },
  { icon: '📊', name: 'ECharts',  role: '数据可视化' },
]
</script>

<style scoped>
.about-page { min-height: 100vh; padding: 40px 0 80px; }
.container { max-width: 1000px; margin: 0 auto; padding: 0 24px; }

.about-section { margin-bottom: 48px; }
.section-heading {
  font-size: 20px;
  font-weight: 700;
  color: var(--text-primary);
  margin-bottom: 20px;
  padding-bottom: 10px;
  border-bottom: 1px solid var(--border-subtle);
}

/* 英雄区 */
.about-hero {
  padding: 48px;
  text-align: center;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 12px;
}
.hero-icon { font-size: 48px; color: var(--sentinel-warning); }
.hero-title { font-size: 36px; font-weight: 800; letter-spacing: 4px; }
.hero-desc { font-size: 16px; color: var(--text-secondary); max-width: 560px; }
.divider-line { width: 60px; height: 2px; background: var(--sentinel-primary-light); border-radius: 1px; margin: 4px 0; }
.intro-text { font-size: 14px; color: var(--text-secondary); max-width: 700px; line-height: 1.9; text-align: left; }

/* 架构图 */
.arch-grid {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}
.arch-card {
  flex: 1;
  min-width: 160px;
  padding: 20px 16px;
  text-align: center;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 8px;
}
.arch-icon { line-height: 1; }
.arch-label { font-size: 14px; font-weight: 600; color: var(--text-primary); }
.arch-desc { font-size: 12px; color: var(--text-muted); line-height: 1.5; }
.arch-arrow { font-size: 20px; color: var(--text-muted); flex-shrink: 0; }

/* 技术栈 */
.tech-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(140px, 1fr));
  gap: 12px;
}
.tech-item {
  padding: 16px;
  text-align: center;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 6px;
  transition: transform var(--transition-fast);
}
.tech-item:hover { transform: translateY(-2px); }
.tech-icon { font-size: 28px; }
.tech-name { font-size: 14px; font-weight: 600; color: var(--text-primary); }
.tech-role { font-size: 11px; color: var(--text-muted); }

/* 团队 */
.team-card { padding: 28px 32px; }
.team-row { display: flex; gap: 40px; flex-wrap: wrap; }
.team-item {}
.team-label { font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.8px; color: var(--text-muted); margin-bottom: 6px; }
.team-value { font-size: 16px; font-weight: 600; color: var(--text-primary); }
.github-link { margin-top: 20px; }
</style>
