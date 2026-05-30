<template>
  <nav class="navbar">
    <div class="navbar-inner">
      <!-- Logo -->
      <RouterLink to="/" class="navbar-logo">
        <span class="logo-icon">⬡</span>
        <span class="logo-text">SENTINEL</span>
        <span class="logo-sub">漏洞审计平台</span>
      </RouterLink>

      <!-- 导航链接 -->
      <div class="navbar-links">
        <RouterLink
          v-for="item in navItems"
          :key="item.path"
          :to="item.path"
          class="nav-link"
          :class="{ active: isActive(item.path) }"
        >
          <el-icon><component :is="item.icon" /></el-icon>
          <span>{{ item.label }}</span>
        </RouterLink>
      </div>
    </div>
  </nav>
</template>

<script setup lang="ts">
import { useRoute } from 'vue-router'

const route = useRoute()

const navItems = [
  { path: '/',       label: '首页',     icon: 'House' },
  { path: '/tasks',  label: '任务列表', icon: 'List' },
  { path: '/about',  label: '关于',     icon: 'InfoFilled' }
]

function isActive(path: string) {
  if (path === '/') return route.path === '/'
  return route.path.startsWith(path)
}
</script>

<style scoped>
.navbar {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  z-index: 1000;
  height: 64px;
  background: rgba(13, 24, 33, 0.95);
  backdrop-filter: blur(12px);
  -webkit-backdrop-filter: blur(12px);
  border-bottom: 1px solid var(--border-subtle);
}

.navbar-inner {
  max-width: 1280px;
  margin: 0 auto;
  height: 100%;
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 24px;
}

.navbar-logo {
  display: flex;
  align-items: center;
  gap: 8px;
  text-decoration: none;
  color: var(--text-primary);
}
.logo-icon {
  font-size: 22px;
  color: var(--sentinel-warning);
  line-height: 1;
}
.logo-text {
  font-size: 18px;
  font-weight: 700;
  letter-spacing: 2px;
  color: var(--text-primary);
}
.logo-sub {
  font-size: 11px;
  color: var(--text-muted);
  margin-left: 2px;
  margin-top: 2px;
  border-left: 1px solid var(--border-subtle);
  padding-left: 8px;
}

.navbar-links {
  display: flex;
  align-items: center;
  gap: 4px;
}

.nav-link {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 6px 16px;
  border-radius: var(--radius-md);
  font-size: 14px;
  font-weight: 500;
  color: var(--text-secondary);
  text-decoration: none;
  transition: color var(--transition-fast), background var(--transition-fast);
}
.nav-link:hover {
  color: var(--text-primary);
  background: rgba(255, 255, 255, 0.06);
}
.nav-link.active {
  color: var(--text-primary);
  background: rgba(30, 74, 120, 0.3);
}
.nav-link.active span {
  color: #5baaff;
}
</style>
