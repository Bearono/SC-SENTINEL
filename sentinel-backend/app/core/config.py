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

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


# 全局单例，供其他模块 from app.core.config import settings 调用
settings = Settings()
