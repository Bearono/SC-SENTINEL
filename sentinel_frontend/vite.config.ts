import { fileURLToPath, URL } from 'node:url'
import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [vue()],
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url))
    }
  },
  server: {
    port: 5173,
    proxy: {
      // 所有 /api 请求代理到后端，解决跨域问题
      '/api': {
        target: 'http://127.0.0.1:18000',
        changeOrigin: true
      },
      // WebSocket 代理
      '/ws': {
        target: 'ws://127.0.0.1:18000',
        ws: true,
        changeOrigin: true
      }
    }
  }
})
