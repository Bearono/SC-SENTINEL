# ============================================================
# SENTINEL Backend Dockerfile
# 同一镜像复用为两个角色：
#   - api    : uvicorn 启动 FastAPI 主服务
#   - worker : taskiq 启动后台任务消费进程
# 角色由 docker-compose 的 command 决定。
# ============================================================
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    TZ=Asia/Shanghai

WORKDIR /app

# ── 系统依赖 ──────────────────────────────────────────────────────────
# - libpq 相关：asyncpg 运行所需
# - curl：容器健康检查
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# ── Python 依赖（先单独 COPY，利用层缓存）──────────────────────────────
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── 应用代码 ──────────────────────────────────────────────────────────
COPY . .

# 上传目录（与 tasks.py 中 UPLOAD_DIR="uploads" 对齐）
RUN mkdir -p /app/uploads

EXPOSE 18000

# 默认以 API 角色启动；worker 角色在 compose 中通过 command 覆盖
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "18000"]
