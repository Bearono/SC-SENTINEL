<template>
  <nav class="nav">
    <RouterLink to="/" class="nlogo">
      <span class="nlmark">
        <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
          <path d="M8 1.5L14 5V11L8 14.5L2 11V5L8 1.5Z" stroke="white" stroke-width="1.1" fill="none" />
          <path d="M8 4.5L11.5 6.5V10.5L8 12.5L4.5 10.5V6.5L8 4.5Z" fill="white" opacity="0.5" />
          <circle cx="8" cy="8.5" r="1.8" fill="white" />
        </svg>
      </span>
      SENTINEL
    </RouterLink>

    <div class="ntabs">
      <button class="ntab" :class="{ active: route.name === 'home' }" @click="go('home')">Overview</button>
      <button class="ntab" :class="{ active: route.name === 'submit' }" @click="go('submit')">New Audit</button>
      <button class="ntab" :class="{ active: route.name === 'monitor' }" @click="goTask('monitor')">Live Monitor</button>
      <button class="ntab" :class="{ active: route.name === 'report' }" @click="goTask('report')">Report</button>
      <button class="ntab" :class="{ active: route.name === 'history' }" @click="go('history')">History</button>
    </div>

    <div class="nright">
      <RouterLink to="/history" class="bp bg">History</RouterLink>
      <RouterLink to="/submit" class="bp bw">Start Audit →</RouterLink>
    </div>
  </nav>
</template>

<script setup lang="ts">
import { useRoute, useRouter } from 'vue-router'
import { useTaskStore } from '@/stores/taskStore'

const route = useRoute()
const router = useRouter()
const store = useTaskStore()

function go(name: string) {
  router.push({ name })
}

// Live Monitor / Report 需要 task id：优先用当前任务，否则跳 History
function goTask(name: 'monitor' | 'report') {
  const id = (route.params.id as string) || store.currentTask?.id
  if (id) router.push({ name, params: { id } })
  else router.push({ name: 'history' })
}
</script>

<style scoped>
.nav {
  position: sticky; top: 0; z-index: 200; height: 58px; padding: 0 44px;
  display: flex; align-items: center; justify-content: space-between;
  background: rgba(253, 252, 252, 0.9); backdrop-filter: blur(20px);
  border-bottom: 1px solid var(--ch);
}
.nlogo { display: flex; align-items: center; gap: 9px; font-family: var(--fd); font-size: 19px; cursor: pointer; color: inherit; }
.nlmark {
  width: 30px; height: 30px; border-radius: 7px; background: var(--obs);
  display: flex; align-items: center; justify-content: center; position: relative; overflow: hidden;
}
.nlmark::before { content: ''; position: absolute; inset: 0; background: linear-gradient(135deg, rgba(255, 107, 53, 0.55), transparent 60%); }
.nlmark svg { position: relative; z-index: 1; }

.ntabs { display: flex; align-items: center; gap: 2px; }
.ntab {
  padding: 6px 15px; border-radius: 9999px; border: 1px solid transparent;
  font-size: 13px; font-weight: 500; color: var(--grv); cursor: pointer;
  background: transparent; transition: all .15s; font-family: var(--fb);
}
.ntab:hover { color: var(--obs); background: var(--pw); }
.ntab.active { color: #fff; background: var(--obs); }

.nright { display: flex; align-items: center; gap: 8px; }

@media (max-width: 860px) {
  .nav { padding: 0 18px; }
  .ntabs { display: none; }
}
</style>
