FROM python:3.11-slim

WORKDIR /app

# 安装依赖
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 复制源码
COPY . .

# 默认暴露 18001
EXPOSE 18001

CMD ["uvicorn", "service:app", "--host", "0.0.0.0", "--port", "18001"]
