"""
全局响应包装器
所有 HTTP 接口（除 WebSocket 外）的响应均使用此格式。
"""
from typing import Any, Optional


def ok(data: Any = None, message: str = "success") -> dict:
    """成功响应"""
    return {"code": 200, "message": message, "data": data}


def fail(code: int, message: str) -> dict:
    """失败响应"""
    return {"code": code, "message": message, "data": None}
