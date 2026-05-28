"""
SENTINEL — FastAPI 应用入口
面向 C/C++ 开源供应链的 eBPF-LLM 协同漏洞审计系统
"""
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.core.database import engine, Base

# 触发所有模型的注册（让 Base.metadata 感知到所有表）
import app.models  # noqa: F401

logger = logging.getLogger(__name__)


# ── 生命周期管理 ────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    应用启动 / 关闭时的钩子。
    开发阶段：启动时自动建表（等价于 create_all）。
    生产阶段：注释掉 create_all，改用 Alembic 做迁移。
    """
    logger.info("🚀 SENTINEL 启动中，正在连接数据库并初始化表结构...")
    async with engine.begin() as conn:
        # 开发用：自动建表（不会覆盖已有表）
        await conn.run_sync(Base.metadata.create_all)
    logger.info("✅ 数据库表结构初始化完毕")
    yield
    # 关闭时清理连接池
    await engine.dispose()
    logger.info("🔒 数据库连接池已释放，SENTINEL 关闭")


# ── FastAPI 实例 ────────────────────────────────────────────────────────────────
app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description=settings.DESCRIPTION,
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# ── CORS 中间件（前端调试用，生产环境按需收紧）──────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── 健康检查路由 ─────────────────────────────────────────────────────────────────
@app.get("/health", tags=["System"])
async def health_check():
    """服务健康检查接口"""
    return {
        "status": "ok",
        "project": settings.PROJECT_NAME,
        "version": settings.VERSION,
    }


# ── API 路由注册 ────────────────────────────────────────────────────────────────
from app.api.v1.router import v1_router  # noqa: E402

app.include_router(v1_router)


if __name__ == "__main__":
    import uvicorn
    import platform
    import asyncio

    if platform.system() == "Windows":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    # 通过 python app/main.py 启动时，开启热重载与指定端口
    uvicorn.run("app.main:app", host="127.0.0.1", port=18000, reload=True)

