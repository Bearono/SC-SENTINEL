import axios from 'axios'
import { ElMessage } from 'element-plus'

const http = axios.create({
  baseURL: '/api/v1',
  timeout: 30000,
  headers: { 'Content-Type': 'application/json' }
})

// ── 请求拦截器 ──────────────────────────────────────────────────
http.interceptors.request.use(
  (config) => config,
  (error) => Promise.reject(error)
)

// ── 响应拦截器（全局异常处理） ────────────────────────────────────
http.interceptors.response.use(
  (response) => {
    const data = response.data
    // 后端业务层错误（code !== 0）
    if (data && typeof data.code === 'number' && data.code !== 0) {
      const msg = data.msg || '操作失败，请稍后重试'
      ElMessage.error(msg)
      return Promise.reject(new Error(msg))
    }
    return response
  },
  (error) => {
    // HTTP 层错误
    if (error.response) {
      const status = error.response.status
      const msgMap: Record<number, string> = {
        400: '请求参数错误',
        404: '请求的资源不存在',
        422: '数据格式校验失败',
        500: '服务器内部错误，请联系管理员',
        503: '服务暂时不可用，请稍后重试'
      }
      const msg = error.response.data?.msg || msgMap[status] || `请求失败 (${status})`
      ElMessage.error(msg)
    } else if (error.code === 'ECONNABORTED') {
      ElMessage.error('请求超时，请检查网络连接')
    } else {
      ElMessage.error('网络异常，无法连接到后端服务')
    }
    return Promise.reject(error)
  }
)

export default http
