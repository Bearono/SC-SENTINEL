# SENTINEL Backend 

## 选用技术栈
- Python 3.11
- FastAPI + Uvicorn
- PostgreSQL 
- SQLAlchemy + asyncpg + Alembic
- TaskIQ + Redis
- Docker SDK + eBPF

目前已完成核心的数据库模型与 API 接口实现。

## 1. 数据库模型实现

目前已完成以下 4 张核心数据表的设计与映射：

### 1.1 Task (任务表)
作为全局调度中心，记录每次审计任务从上传到出报告的完整生命周期。
*   `id` (UUID): 主键，唯一任务流水号
*   `project_name` (String): 项目名称
*   `source_type` (Enum): 源码来源 (zip / github)
*   `source_path` (Text): 源码文件存储路径或 GitHub 仓库地址
*   `status` (Enum): 任务当前阶段 (pending, analyzing_deps, llm_auditing, fuzzing, completed, failed)
*   `target_vulns` (Text): 用户自定义漏洞扫描配置（JSON 字符串）
*   `is_dynamic` (Boolean): 是否开启 eBPF 动态验证
*   `error_message` (Text): 任务失败时的错误原因
*   `created_at` (DateTime): 任务创建时间
*   `completed_at` (DateTime): 任务完成时间

### 1.2 ComponentRisk (组件风险表)
记录项目引入的第三方开源库的已知漏洞（CVE）。
*   `id` (UUID): 主键
*   `task_id` (UUID): 关联的审计任务 ID
*   `library_name` (String): 开源库名称
*   `version` (String): 版本号
*   `cve_id` (String): CVE 漏洞编号
*   `cvss_score` (Float): CVSS 漏洞严重评分
*   `severity` (Enum): 危险等级 (critical, high, medium, low, unknown)
*   `nvd_url` (Text): 漏洞详情的 NVD 链接
*   `description` (Text): 漏洞简述

### 1.3 Vulnerability (漏洞表)
记录大模型与静态分析工具扫出的核心可疑点，并跟踪动态沙箱的实锤验证状态。
*   `id` (UUID): 主键
*   `task_id` (UUID): 关联的审计任务 ID
*   `vuln_type` (String): 漏洞类型 (如 UAF、堆溢出)
*   `file_path` (Text): 漏洞所在文件路径
*   `line_number` (Integer): 漏洞所在行号
*   `code_context` (Text): 漏洞所在代码片段（供前端高亮展示）
*   `trigger_cond` (Text): AI 触发条件描述
*   `fix_advice` (Text): AI 给出的修复建议
*   `verify_status` (Enum): 验证状态 (unverified, confirmed, false_positive)
*   `afl_log` (Text): AFL++ 产生的原始崩溃日志

### 1.4 EbpfEventLog (内核事件表)
存放 eBPF 动态沙箱从内核层截获的内存非法操作（实锤铁证）。
*   `id` (UUID): 主键
*   `vuln_id` (UUID): 关联到具体漏洞的 ID
*   `timestamp` (BigInteger): 内核事件精确时间戳（纳秒级）
*   `event_type` (Enum): 内核事件类型 (如 double_free, null_deref)
*   `function_name` (String): 触发异常的函数名
*   `memory_addr` (String): 异常发生时的内存地址（十六进制字符串）
*   `stack_trace` (Text): 内核调用栈
*   `raw_data` (Text): 原始 JSON 数据

---

## 2. API 接口实现

除 WebSocket 与文件下载接口外，所有 HTTP 接口的成功/失败响应均遵循全局规范包裹：
```json
{
  "code": 200,          
  "message": "success", 
  "data": {}            // 下文接口详情中的 "返回 data" 即指代此字段内的核心业务数据
}
```

### 2.1 提交任务与源码上传
*   **URL**: `POST /api/v1/tasks`
*   **功能**: 接收文件或 URL，创建审计任务。
*   **返回 data 结构**:
    ```json
    {
      "id": "uuid",
      "project_name": "项目名称",
      "status": "pending",
      "created_at": "2026-05-28T12:00:00Z"
    }
    ```

### 2.2 获取任务列表
*   **URL**: `GET /api/v1/tasks`
*   **功能**: 分页查询历史任务。
*   **返回 data 结构**:
    ```json
    {
      "total": 100,
      "items": [
        { "id": "uuid", "project_name": "...", "status": "...", "created_at": "..." }
      ]
    }
    ```

### 2.3 触发审计 Pipeline
*   **URL**: `POST /api/v1/audit/submit`
*   **功能**: 根据已创建的 `task_id` 触发后台异步流水线（SBOM → LLM → 可选 Fuzzing）。
*   **请求体**: `{ "task_id": "uuid" }`
*   **返回 data 结构**:
    ```json
    {
      "task_id": "uuid",
      "status": "pending",
      "ws_url": "/api/v1/ws/tasks/{task_id}/progress"
    }
    ```

### 2.4 查询审计进度（降级轮询）
*   **URL**: `GET /api/v1/audit/status/{task_id}`
*   **功能**: 返回任务当前阶段、进度百分比和 WebSocket 地址，供前端 WebSocket 断开时阭降级轮询。
*   **返回 data 结构**:
    ```json
    {
      "task_id": "uuid",
      "project_name": "...",
      "status": "llm_auditing",
      "status_label": "LLM Multi-Agent 静态审计中",
      "progress_percent": 60,
      "ws_url": "/api/v1/ws/tasks/{task_id}/progress"
    }
    ```

### 2.5 查询单体任务
*   **URL**: `GET /api/v1/tasks/{task_id}`
*   **功能**: 获取任务当前的基本执行状态。
*   **返回 data 结构**: 小于 2.4，仅返回 `id`、`status`、`created_at`。

### 2.6 获取聚合报告
*   **URL**: `GET /api/v1/tasks/{task_id}/report`
*   **功能**: 任务完成后调用，通过四表联查返回最终聚合审计数据。
*   **返回 data 结构**:
    ```json
    {
      "summary": {
        "project_name": "...",
        "total_time_seconds": 45.2,
        "is_dynamic": true
      },
      "components": [
        { "library_name": "...", "version": "...", "cve_id": "...", "severity": "..." }
      ],
      "vulnerabilities": [
        {
          "id": "uuid",
          "vuln_type": "UAF",
          "file_path": "...",
          "line_number": 42,
          "verify_status": "confirmed",
          "ebpf_logs": [
            { "timestamp": 123456789, "event_type": "double_free", "memory_addr": "0xff...", "function_name": "..." }
          ]
        }
      ]
    }
    ```

### 2.7 强制终止任务
*   **URL**: `POST /api/v1/tasks/{task_id}/cancel`
*   **功能**: 强制中断正在运行的任务。
*   **返回 data 结构**: `null`

### 2.8 实时进度流 (WebSocket)
*   **URL**: `WS /api/v1/ws/tasks/{task_id}/progress`
*   **功能**: 提供 WebSocket 双向长连接，用于向前端实时推送审计日志与进度百分比（无全局 JSON 包裹）。
*   **推送格式**:
    ```json
    {
      "stage": "fuzzing",
      "percent": 80,
      "message": "正在进行 eBPF 动态验证...",
      "log_stream": "[+] AFL++ launched on core 1\n"
    }
    ```

### 2.9 导出 PDF 报告
*   **URL**: `GET /api/v1/tasks/{task_id}/export-pdf`
*   **功能**: 动态生成含有颜色告警与漏洞代码的高质量 PDF 审计报告。
*   **返回内容**: 直接返回二进制文件流，`Content-Type: application/pdf`，触发浏览器直接下载。

---

## 3. 核心引擎与基础设施实现

### 3.1 异步任务后台处理
TaskIQ + Redis 后台任务队列

### 3.2 动态沙箱管理 (Docker)
为了防止恶意代码弄坏服务器，只要到了测试漏洞（Fuzzing）的阶段，后端就会自动用代码临时建一个 Docker 容器，把测试放到这个“沙箱”里面跑，跑完或者报错就会自动删掉，保证安全。

### 3.3 eBPF 内核级漏洞监控
在沙箱跑程序的时候，一旦它发生了 UAF 或 Double Free 这种内存漏洞，立刻抓到崩溃那一瞬间的日志。

### 3.4 WebSocket 实时进度推送
后端在跑大模型或者抓漏洞的时候，会把每一步在干什么（比如“正在分析依赖...”）像终端打字一样实时推给前端页面。

### 3.5 联调模拟模式 (Mock)
假的联调模式。在这个模式下，后端不会真的去跑大模型和 Fuzzing。
