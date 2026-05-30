from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    PROJECT_NAME: str = "SENTINEL"
    VERSION: str = "0.1.0"
    DESCRIPTION: str = "面向 C/C++ 开源供应链的 eBPF-LLM 协同漏洞审计系统"
    API_V1_PREFIX: str = "/api/v1"

    # 数据库异步连接 URL
    # 格式: postgresql+asyncpg://用户名:密码@主机:端口/数据库名
    # 优先从 .env 文件或环境变量读取，否则使用下面的默认值
    DATABASE_URL: str = (
        "postgresql+asyncpg://sentinel_admin:123456@127.0.0.1:5433/sentinel_db"
    )

    # Redis 连接 URL（与 docker-compose.yaml 中 sentinel_redis 保持一致）
    # docker-compose 映射：宿主机 6380 → 容器内 6379
    REDIS_URL: str = "redis://127.0.0.1:6380/0"

    # ── ML 队友的 Agent 接口地址 ───────────────────────────────────────────────
    # ML-A 同学负责的 Agent A（依赖 CVE 查询）接口
    ML_AGENT_A_URL: str = "http://127.0.0.1:18001/api/agent-a/analyze"
    # ML-B 同学负责的 Agent B（源码漏洞审计）接口
    ML_AGENT_B_URL: str = "http://127.0.0.1:18001/api/agent-b/audit"

    # ── ML Mock 模式开关 ───────────────────────────────────────────────────────
    # 设置为 true 时，不实际调用 ML 接口，使用内置 Demo 数据代替。
    # 目的：在 ML 同学接口未就绪期间，后端仍可独立演示完整流程。
    # 生产环境或联调时将此值改为 false。
    ML_MOCK_MODE: bool = True

    # ── Docker 沙箱配置 ────────────────────────────────────────────────────────
    # 沙箱镜像名称（需提前 docker build 构建）
    SANDBOX_IMAGE: str = "sentinel-sandbox:latest"
    # 单次动态验证任务的最大运行时间（秒），超时后强制销毁容器
    # 执行手册：「运行 5 分钟，收集崩溃样本」
    SANDBOX_TIMEOUT_SECONDS: int = 360   # 6 分钟（含编译 + eBPF 启动 + AFL 运行）
    # 沙箱容器 CPU 限制（纳秒/100ms，即 nano_cpus；1 核 = 1_000_000_000）
    SANDBOX_CPU_QUOTA: int = 1_000_000_000  # 限制 1 核
    # 沙箱容器内存限制（字节），防止 OOM 拖垮宿主机
    SANDBOX_MEM_LIMIT: str = "1g"   # 1 GB

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


# 全局单例，供其他模块 from app.core.config import settings 调用
settings = Settings()
