/**
 * WebSocket 生命周期管理 Composable
 * 负责：连接建立 / 心跳 / 异常断开 / 自动重连 / 与 3 秒轮询的互斥
 */
import { ref, onUnmounted } from 'vue'
import { useTaskStore } from '@/stores/taskStore'
import type { WsProgressMessage } from '@/types/api'

export function useWebSocket(taskId: string) {
  const store = useTaskStore()
  const ws = ref<WebSocket | null>(null)
  let reconnectTimer: ReturnType<typeof setTimeout> | null = null
  let heartbeatTimer: ReturnType<typeof setInterval> | null = null
  let reconnectAttempts = 0
  const MAX_RECONNECT = 5
  const HEARTBEAT_INTERVAL = 30000

  function connect() {
    if (ws.value && ws.value.readyState === WebSocket.OPEN) return

    // 代理配置下直接使用相对路径 /ws/...
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const url = `${protocol}//${window.location.host}/ws/api/v1/ws/tasks/${taskId}/progress`

    ws.value = new WebSocket(url)
    store.wsConnected = false

    ws.value.onopen = () => {
      store.wsConnected = true
      reconnectAttempts = 0
      startHeartbeat()
      console.log(`[WS] Connected for task ${taskId}`)
    }

    ws.value.onmessage = (event) => {
      try {
        const msg: WsProgressMessage = JSON.parse(event.data)
        // 忽略 pong 心跳
        if ((msg as unknown as { type: string }).type === 'pong') return
        store.pushProgressLog(msg)
      } catch {
        console.warn('[WS] Failed to parse message:', event.data)
      }
    }

    ws.value.onclose = (event) => {
      store.wsConnected = false
      stopHeartbeat()
      console.log(`[WS] Closed (code=${event.code}) for task ${taskId}`)
      // 非正常关闭时自动重连
      if (event.code !== 1000 && reconnectAttempts < MAX_RECONNECT) {
        scheduleReconnect()
      }
    }

    ws.value.onerror = (err) => {
      console.error('[WS] Error:', err)
      ws.value?.close()
    }
  }

  function scheduleReconnect() {
    if (reconnectTimer) return
    const delay = Math.min(1000 * 2 ** reconnectAttempts, 15000)
    reconnectAttempts++
    console.log(`[WS] Reconnecting in ${delay}ms (attempt ${reconnectAttempts})`)
    reconnectTimer = setTimeout(() => {
      reconnectTimer = null
      connect()
    }, delay)
  }

  function startHeartbeat() {
    heartbeatTimer = setInterval(() => {
      if (ws.value?.readyState === WebSocket.OPEN) {
        ws.value.send(JSON.stringify({ type: 'ping' }))
      }
    }, HEARTBEAT_INTERVAL)
  }

  function stopHeartbeat() {
    if (heartbeatTimer) {
      clearInterval(heartbeatTimer)
      heartbeatTimer = null
    }
  }

  function disconnect() {
    stopHeartbeat()
    if (reconnectTimer) {
      clearTimeout(reconnectTimer)
      reconnectTimer = null
    }
    if (ws.value) {
      ws.value.close(1000, 'Component unmounted')
      ws.value = null
    }
    store.wsConnected = false
  }

  onUnmounted(disconnect)

  return { connect, disconnect, wsConnected: store.wsConnected }
}
