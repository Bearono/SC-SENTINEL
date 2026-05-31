# 对接规范

---

## 1. Agent A

**输出要求**：将分析结果以 JSON 格式返回，结构如下：
```json
{
  "components": [
    {
      "library_name": "openssl",
      "version": "1.0.1e",
      "cve_id": "CVE-2014-0160",
      "cvss_score": 7.8,
      "severity": "high",
      "description": "Heartbleed: The TLS heartbeat extension reads up to 64KB beyond the buffer...",
      "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2014-0160"
    }
  ]
}
```
**数据约束**：
1. 顶层必须是 `{ "components": [...] }` 结构，不可直接返回数组。
2. `severity` 字段为以下全小写枚举值之一：`critical`, `high`, `medium`, `low`, `unknown`。该字段直接影响前端颜色渲染。

---

## 2. Agent B/C

**输出要求**：将审计结果以 JSON 格式返回，结构如下：
```json
{
  "vulnerabilities": [
    {
      "vuln_type": "Use-After-Free",
      "file_path": "src/ssl/ssl_lib.c",
      "line_number": 1234,
      "code_context": "1232: free(buf);\n1234: memcpy(out, buf, len);",
      "trigger_cond": "当 SSL 握手在特定序列下调用此函数...",
      "fix_advice": "free 后立即置 NULL，使用前校验..."
    }
  ]
}
```
**数据约束**：
1. 顶层必须是 `{ "vulnerabilities": [...] }` 结构，不可直接返回数组。
2. `file_path` 为基于项目根目录的**相对路径**。
3. `vuln_type` 需采用以下标准缩写之一：`UAF`、`double_free`、`heap_overflow`、`stack_overflow`。

---

## 3. eBPF + AFL++

沙箱验证结束后，以 Python 字典列表的形式返回捕获到的 eBPF 内核事件，每条事件格式如下：

> **注意**：eBPF 事件使用短键名，与前两个 Agent 的风格不同。

```json
[
  {
    "ts":    1680001234567890,
    "event": "double_free",
    "addr":  "0xffff888100123456",
    "fn":    "sys_free",
    "stack": "#0 sys_free\n#1 do_something"
  }
]
```
**数据约束**：
1. `ts` 为纳秒级整型时间戳。
2. `event` 字段接受：`double_free`, `use_after_free`, `heap_overflow`, `null_deref`, `stack_overflow`, `out_of_bounds`。
3. `addr` 为标准十六进制字符串。
4. AFL++ 崩溃日志通过 `SandboxResult.afl_crash_log` 字段单独传递（非 eBPF 事件列表的一部分）。

---

## 4. 实时日志推送

各模块可在关键生命周期节点调用以下接口，用于向前端 WebSocket 推送实时进度：

`ws_manager.broadcast(task_id, payload)`

`payload` 格式：
```json
{
  "stage":      "llm_auditing",
  "percent":    60,
  "message":    "正在分析漏洞...",
  "log_stream": "底层终端的原始输出\n"
}
```
- `stage`：当前执行阶段，枚举值：`pending`, `analyzing_deps`, `llm_auditing`, `fuzzing`, `done`。
- `percent`：0-100 的整数进度百分比。
