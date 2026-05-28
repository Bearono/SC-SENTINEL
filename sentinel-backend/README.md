# SENTINEL Backend 

## 选用技术栈
- Python 3.11
- FastAPI + Uvicorn
- PostgreSQL 
- SQLAlchemy + asyncpg + Alembic

目前已完成核心的数据库模型与 API 接口实现。

## 1. 数据库模型实现 (Database Models)

目前已完成以下 4 张核心数据表的设计与 Alembic 迁移配置，详细字段如下：

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
*   `created_at` / `completed_at` (DateTime): 创建与完成时间

### 1.2 ComponentRisk (组件风险表)
记录项目引入的第三方开源库的已知漏洞（CVE）。
*   `id` (UUID): 主键
*   `task_id` (UUID): 关联的审计任务 ID
*   `library_name` (String): 开源库名称
*   `version` (String): 版本号
*   `cve_id` (String): CVE 漏洞编号
*   `cvss_score` (Float): CVSS 漏洞严重评分
*   `severity` (Enum): 危险等级 (critical, high, medium, low, unknown)
*   `nvd_url` / `description` (Text): 漏洞详情链接与简述

### 1.3 Vulnerability (漏洞表)
记录大模型与静态分析工具扫出的核心可疑点，并跟踪动态沙箱的实锤验证状态。
*   `id` (UUID): 主键
*   `task_id` (UUID): 关联的审计任务 ID
*   `vuln_type` (String): 漏洞类型 (如 UAF、堆溢出)
*   `file_path` / `line_number` (Text/Integer): 漏洞所在文件路径及行号
*   `code_context` (Text): 漏洞所在代码片段（供前端高亮展示）
*   `trigger_cond` / `fix_advice` (Text): AI 触发条件描述与修复建议
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
*   `stack_trace` / `raw_data` (Text): 内核调用栈与原始 JSON 数据

---

## 2. API 接口实现 (API Matrix)

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

### 2.3 查询单体任务
*   **URL**: `GET /api/v1/tasks/{task_id}`
*   **功能**: 获取任务当前的基本执行状态，供前端静默轮询使用。
*   **返回 data 结构**: 同 `2.1` 提交任务的返回结构 (`id`, `status`, `created_at`)。

### 2.4 获取聚合报告
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

### 2.5 强制终止任务
*   **URL**: `POST /api/v1/tasks/{task_id}/cancel`
*   **功能**: 强制中断正在运行的任务。
*   **返回 data 结构**: `null`

### 2.6 实时进度流 (WebSocket)
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

### 2.7 导出 PDF 报告
*   **URL**: `GET /api/v1/tasks/{task_id}/export-pdf`
*   **功能**: 动态生成含有颜色告警与漏洞代码的高质量 PDF 审计报告。
*   **返回内容**: 直接返回二进制文件流，`Content-Type: application/pdf`，触发浏览器直接下载。
