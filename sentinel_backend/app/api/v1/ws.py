"""
WebSocket 接口实现
WS /api/v1/ws/tasks/{task_id}/progress — 实时进度流推送
"""
import uuid

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.core.ws_manager import ws_manager

ws_router = APIRouter(prefix="/ws", tags=["WebSocket"])


@ws_router.websocket("/tasks/{task_id}/progress")
async def task_progress_ws(task_id: uuid.UUID, websocket: WebSocket):
    """
    建立 WebSocket 长连接，实时推送审计进度日志。

    推送格式（由后台任务主动调用 ws_manager.broadcast() 发送）：
    {
        "stage":      "fuzzing",
        "percent":    75,
        "message":    "AFL++ running... eBPF uprobe attached to malloc()",
        "log_stream": "[+] Captured double free exception at 0x7ff000..."
    }

    注意：此接口不经过全局 HTTP 响应包装器。
    """
    task_id_str = str(task_id)
    await ws_manager.connect(task_id_str, websocket)

    # 连接建立后，立即推送一条握手确认消息
    await websocket.send_json({
        "stage": "connected",
        "percent": 0,
        "message": f"已成功连接到任务 {task_id_str} 的实时进度流",
        "log_stream": "",
    })

    try:
        # 保持连接活跃，接收来自前端的心跳 ping（如有）
        while True:
            data = await websocket.receive_text()
            # 前端发 "ping" 时，服务端回应 "pong"（保活机制）
            if data.strip().lower() == "ping":
                await websocket.send_text("pong")

    except WebSocketDisconnect:
        ws_manager.disconnect(task_id_str, websocket)
