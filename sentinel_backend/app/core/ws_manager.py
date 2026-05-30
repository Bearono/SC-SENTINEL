"""
WebSocket 连接管理器
维护一个「task_id → [WebSocket连接列表]」的映射，
支持后台任务在任意时刻向前端广播实时日志推送。
"""
import logging
from typing import Dict, List

from fastapi import WebSocket

logger = logging.getLogger(__name__)


class ConnectionManager:
    """
    管理所有活跃的 WebSocket 连接。
    一个 task_id 可以同时被多个前端标签页监听（多连接广播）。
    """

    def __init__(self):
        # { "task_id_str": [WebSocket, WebSocket, ...] }
        self.active: Dict[str, List[WebSocket]] = {}

    async def connect(self, task_id: str, websocket: WebSocket) -> None:
        """接受新的 WebSocket 握手，并注册到对应任务的连接池"""
        await websocket.accept()
        self.active.setdefault(task_id, []).append(websocket)
        logger.info(f"[WS] 客户端已接入 task={task_id}，当前连接数={len(self.active[task_id])}")

    def disconnect(self, task_id: str, websocket: WebSocket) -> None:
        """从连接池中移除已断开的 WebSocket"""
        if task_id in self.active:
            try:
                self.active[task_id].remove(websocket)
            except ValueError:
                pass
            if not self.active[task_id]:
                del self.active[task_id]
        logger.info(f"[WS] 客户端已断开 task={task_id}")

    async def broadcast(self, task_id: str, message: dict) -> None:
        """
        向指定任务的所有已连接客户端广播 JSON 消息。
        自动清理已失效的连接（发送失败时移除）。
        """
        if task_id not in self.active:
            return
        dead: List[WebSocket] = []
        for ws in self.active[task_id]:
            try:
                await ws.send_json(message)
            except Exception as e:
                logger.warning(f"[WS] 推送失败，标记为失效连接: {e}")
                dead.append(ws)
        for ws in dead:
            self.disconnect(task_id, ws)

    def get_connection_count(self, task_id: str) -> int:
        """返回指定任务当前的 WebSocket 活跃连接数"""
        return len(self.active.get(task_id, []))


# 全局单例，供后台任务调用 ws_manager.broadcast() 推送进度
ws_manager = ConnectionManager()
