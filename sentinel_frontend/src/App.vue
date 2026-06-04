<template>
  <div id="app-wrapper">
    <div id="cur-glow" />
    <AppNavbar />
    <main class="main-content">
      <RouterView v-slot="{ Component }">
        <Transition name="page" mode="out-in">
          <component :is="Component" />
        </Transition>
      </RouterView>
    </main>
  </div>
</template>

<script setup lang="ts">
import { onMounted, onUnmounted } from 'vue'
import AppNavbar from '@/components/layout/AppNavbar.vue'

// 复刻 example 的光标辉光跟随效果
let gx = 0, gy = 0, mx = 0, my = 0
let raf = 0
const glow = () => document.getElementById('cur-glow')

function onMove(e: MouseEvent) { mx = e.clientX; my = e.clientY }
function lerp(a: number, b: number, t: number) { return a + (b - a) * t }
function loop() {
  gx = lerp(gx, mx, 0.06); gy = lerp(gy, my, 0.06)
  const el = glow()
  if (el) { el.style.left = gx + 'px'; el.style.top = gy + 'px' }
  raf = requestAnimationFrame(loop)
}

onMounted(() => {
  document.addEventListener('mousemove', onMove)
  raf = requestAnimationFrame(loop)
})
onUnmounted(() => {
  document.removeEventListener('mousemove', onMove)
  cancelAnimationFrame(raf)
})
</script>

<style scoped>
#app-wrapper { min-height: 100vh; display: flex; flex-direction: column; }
.main-content { flex: 1; }
</style>
