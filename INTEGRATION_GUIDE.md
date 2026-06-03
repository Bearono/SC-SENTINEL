# SC-SENTINEL Integration Guide

本文档描述 SC-SENTINEL 当前代码中的主要模块契约，供前端、后端、ML、动态验证联调使用。

## 1. 模块边界

| 模块 | 责任 | 主要路径 |
|---|---|---|
| Frontend | 提交任务、查看状态、展示报告和实时日志 | `sentinel_frontend/` |
| Backend API | HTTP/WebSocket API、任务状态、数据库、PDF | `sentinel_backend/app/api/` |
| Backend Worker | SBOM、LLM audit、Fuzzing、Finalize 异步阶段 | `sentinel_backend/app/worker/` |
| ML Agent Service | Agent A-G 七 Agent 审计服务 | `sentinel_agent/service.py` |
| Dynamic Sandbox | Docker、AFL++、eBPF、ASan 证据采集 | `sentinel_backend/docker/`, `sentinel_agent/validation/` |

推荐联调顺序：

```text
Frontend
  -> Backend /api/v1/tasks
  -> Backend /api/v1/audit/submit
  -> Worker SBOM -> ML Agent A
  -> Worker LLM -> ML Agent B-G
  -> optional Worker Fuzzing
  -> Backend report API
  -> Frontend report view
```

## 2. Backend API 契约

后端 HTTP API 使用统一包装：

```json
{
  "code": 200,
  "message": "success",
  "data": {}
}
```

WebSocket 和 ML Agent Service 不使用这个包装。

任务状态建议统一为：

```text
pending
analyzing_deps
llm_auditing
fuzzing
completed
failed
```

### 创建任务

```text
POST /api/v1/tasks
```

核心语义字段：

| 字段 | 类型 | 说明 |
|---|---|---|
| `project_name` | string | 项目名称 |
| `source_type` | string | `zip` 或 `github` |
| `source_path` | string | 本地源码路径、ZIP 路径或 GitHub URL |
| `target_vulns` | array/string | 目标漏洞类型 |
| `is_dynamic` | boolean | 是否启用动态验证 |

### 触发审计

```text
POST /api/v1/audit/submit
```

请求：

```json
{
  "task_id": "uuid"
}
```

返回 `data`：

```json
{
  "task_id": "uuid",
  "status": "pending",
  "ws_url": "/api/v1/ws/tasks/{task_id}/progress"
}
```

### WebSocket 进度

```text
WS /api/v1/ws/tasks/{task_id}/progress
```

推送消息：

```json
{
  "stage": "llm_auditing",
  "percent": 60,
  "message": "正在进行 ML 七 Agent 静态审计",
  "log_stream": "[Agent D] audited 5 hypotheses\n"
}
```

## 3. ML Agent Service

启动方式：

```bash
cd sentinel_agent
python -m uvicorn service:app --host 127.0.0.1 --port 18001
```

后端配置：

```text
ML_MOCK_MODE=false
ML_AGENT_A_URL=http://127.0.0.1:18001/api/agent-a/analyze
ML_AGENT_B_URL=http://127.0.0.1:18001/api/agent-b/audit
```

### Health

```text
GET /health
```

返回：

```json
{
  "status": "ok",
  "service": "sentinel-ml-agent",
  "version": "0.2.0"
}
```

### Agent A: 依赖/CVE 分析

```text
POST /api/agent-a/analyze
```

请求：

```json
{
  "source_root": "E:/path/to/source",
  "dep_files": [],
  "includes": ["openssl/ssl.h"],
  "cpp_files": ["src/main.c"]
}
```

返回：

```json
{
  "components": [
    {
      "library_name": "openssl",
      "version": "1.1.1",
      "cve_id": "CVE-xxxx-yyyy",
      "cvss_score": 7.8,
      "severity": "high",
      "description": "...",
      "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-xxxx-yyyy"
    }
  ],
  "summary": {
    "total_components": 6,
    "high_risk_components": 2,
    "queried_sources": ["OSV", "NVD"]
  },
  "agent_a": {
    "components_rich": []
  }
}
```

后端落库只需要顶层 `components`。`agent_a.components_rich` 供 ML 报告和调试使用。

### Agent B-G: 七 Agent 静态审计、Harness、证据归因、报告

```text
POST /api/agent-b/audit
```

请求：

```json
{
  "source_root": "E:/path/to/source",
  "cpp_files": ["src/main.c"],
  "target_vulns": ["UAF", "heap_overflow", "double_free"],
  "generate_harness": true
}
```

返回：

```json
{
  "vulnerabilities": [
    {
      "vuln_type": "UAF",
      "file_path": "uaf_demo.c",
      "line_number": 12,
      "code_context": "Pointer 'p' is freed ...",
      "trigger_cond": "Pointer is dereferenced after free.",
      "fix_advice": "Set pointer to NULL after free."
    }
  ],
  "summary": {
    "components": {},
    "slices": {},
    "hypotheses": {},
    "findings": {},
    "harness": {},
    "evidence": {},
    "overall_risk": "high"
  },
  "artifacts": {
    "output_dir": "...",
    "harness_dir": "...",
    "final_report_json": ".../final_report.json",
    "final_report_md": ".../final_report.md"
  },
  "agent_a": {},
  "agent_b": {},
  "agent_c": {
    "hypotheses": []
  },
  "agent_d": {
    "static_findings": []
  },
  "agent_e": {
    "harness_packages": []
  },
  "agent_f": {
    "evidence_links": []
  },
  "agent_g": {
    "final_report": {}
  },
  "final_report": {}
}
```

后端落库只需要顶层 `vulnerabilities`。完整 Agent 输出供 ML 调试、演示和导出报告使用。

## 4. 标准字段取值

组件风险等级：

```text
critical
high
medium
low
unknown
```

后端漏洞类型：

```text
UAF
double_free
heap_overflow
stack_overflow
format_string
unknown
```

CWE 映射：

| CWE | 后端类型 |
|---|---|
| `CWE-416` | `UAF` |
| `CWE-415` | `double_free` |
| `CWE-122` | `heap_overflow` |
| `CWE-121` | `stack_overflow` |
| `CWE-134` | `format_string` |

验证状态：

```text
unverified
confirmed
false_positive
```

## 5. 动态验证数据

Agent F 支持归因以下证据：

- ASan: `sentinel_agent/validation/asan_validation_results.json`
- AFL++: `crash_found`、`crash_file`、`asan_bug_type`、`stderr_excerpt`
- eBPF: `events` 列表，事件字段可使用 `event_type` 或 `event`

证据等级：

| 等级 | 含义 |
|---|---|
| `strong` | ASan + AFL++ 或 eBPF |
| `high` | ASan 单独确认 |
| `medium` | AFL++ 或 eBPF 部分证据 |
| `weak` | 无动态证据 |

## 6. 联调注意事项

1. 后端默认 `ML_MOCK_MODE=true`，此时不会调用真实 ML 服务。
2. 真实联调前先启动 `sentinel_agent/service.py`，再启动后端 Worker。
3. ML 服务返回没有全局 `{code,message,data}` 包装，后端 Worker 直接读取顶层字段。
4. `source_root` 必须是 ML 服务所在机器可访问的本地路径。
5. 当前 ASan 证据最可靠；AFL++/eBPF 是增强证据，不建议在汇报中说它们已经完整覆盖所有 CWE。
6. 前端字段若与本文档冲突，建议以本文档和后端实际 schema 为准统一修改。

