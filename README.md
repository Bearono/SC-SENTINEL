# SC-SENTINEL

面向 C/C++ 开源供应链的 eBPF-LLM 协同漏洞审计与安全管理系统。

SENTINEL 的目标是把“依赖风险识别、源码语义审计、Harness 生成、动态验证、报告管理”串成一条可演示、可联调、可继续扩展的安全审计流水线。项目当前由三部分组成：

| 模块 | 路径 | 作用 |
|---|---|---|
| ML 七 Agent | `sentinel_agent/` | 依赖/CVE 分析、语义切片、漏洞假设、LLM 审计、Harness、动态证据归因、最终报告 |
| 后端服务 | `sentinel_backend/` | FastAPI、任务调度、数据库持久化、WebSocket、Docker 沙箱、PDF 导出 |
| 前端界面 | `sentinel_frontend/` | Vue 3 审计任务提交、任务列表、报告展示、实时进度 |

## 1. 系统设计

升级后的 ML 链路如下：

```text
C/C++ 项目输入
  -> Agent A: 依赖情报与 CVE 风险查询
  -> Agent B: 语义切片与 dataflow hints
  -> Agent C: 漏洞假设生成
  -> Agent D: LLM 审计与规则交叉验证
  -> Agent E: Harness 生成与质量门控
  -> Agent F: ASan / AFL++ / eBPF 动态证据归因
  -> Agent G: 最终风险裁决与报告
```

后端接口保持不变：

- `POST /api/agent-a/analyze`
- `POST /api/agent-b/audit`
- `GET /health`

## 2. 当前实现状态

ML 部分位于 `sentinel_agent/`，当前实现能力包括：

- Agent A 从 `#include`、CMake、Makefile、vcpkg、Conan 中识别 C/C++ 第三方组件，并输出 `components_rich`、`component_confidence`、`risk_profile`。
- Agent B 提取函数体、上下文、简单调用关系、风险关键词、`risk_score`、`audit_priority`、`dataflow_hints` 和 `source_sink_pairs`。
- Agent C 只生成漏洞假设，覆盖 UAF、double free、heap/stack overflow、format string。
- Agent D 只对 Agent C 假设做 LLM 审计；LLM 不可用时使用 rule fallback，并保留质量控制信息。
- Agent E 生成 ASan/AFL++/libFuzzer Harness，并记录 `prototype_confidence`、`build_ready`、`manual_adaptation_required`、`compile_check`。
- Agent F 将 ASan/AFL++/eBPF 动态证据归因到具体 finding。
- Agent G 聚合 A-F，生成 `final_report.json` 与 `final_report.md`，并提供审计追踪链路。

最新样例验证结果：

```text
Components: 6
Hypotheses: 5
Static Findings: 5
Harness Packages: 5
Confirmed Findings: 4
ASan Confirmed Findings: 4
Overall Risk: high
```

说明：当前真实动态闭环最扎实的是 ASan。AFL++ 与 eBPF 在后端沙箱侧已有接口和脚本基础，但完整实锤能力仍属于后续增强方向。

## 3. 快速运行 ML 七 Agent

```bash
cd sentinel_agent
pip install -r requirements.txt
python main.py --project samples/vulnerable_project
```

运行完成后主要产物位于：

```text
sentinel_agent/outputs/agent_a_components.json
sentinel_agent/outputs/agent_b_slices.json
sentinel_agent/outputs/agent_c_hypotheses.json
sentinel_agent/outputs/agent_d_findings.json
sentinel_agent/outputs/agent_e_harness_packages.json
sentinel_agent/outputs/agent_f_evidence_links.json
sentinel_agent/outputs/agent_g_final_decision.json
sentinel_agent/outputs/final_report.json
sentinel_agent/outputs/final_report.md
```

旧文件名 `agent_c_findings.json`、`agent_d_harness_packages.json` 仍会生成，方便兼容既有演示材料。

## 4. 启动 ML HTTP 服务

```bash
cd sentinel_agent
python -m uvicorn service:app --host 127.0.0.1 --port 18001
```

健康检查：

```bash
curl http://127.0.0.1:18001/health
```

Agent A 示例：

```bash
curl -X POST http://127.0.0.1:18001/api/agent-a/analyze \
  -H "Content-Type: application/json" \
  -d "{\"source_root\":\"samples/vulnerable_project\"}"
```

Agent B-G 示例：

```bash
curl -X POST http://127.0.0.1:18001/api/agent-b/audit \
  -H "Content-Type: application/json" \
  -d "{\"source_root\":\"samples/vulnerable_project\",\"generate_harness\":true}"
```

## 5. 后端联调方式

启动 ML 服务后，在后端环境中关闭 Mock：

```text
ML_MOCK_MODE=false
ML_AGENT_A_URL=http://127.0.0.1:18001/api/agent-a/analyze
ML_AGENT_B_URL=http://127.0.0.1:18001/api/agent-b/audit
```

后端仍然只需要读取：

- Agent A 顶层 `components`
- Agent B-G 顶层 `vulnerabilities`

完整七 Agent 结构会额外返回在 `agent_a` 到 `agent_g` 字段中，供 ML 调试、演示和报告使用。

## 6. LLM 配置

如果要启用真实 LLM 审计，请在 `sentinel_agent/.env` 或运行环境中配置：

```text
LLM_API_KEY=your_api_key
LLM_BASE_URL=https://your-provider.example/v1
LLM_MODEL=your_model
LLM_TIMEOUT=60
LLM_TEMPERATURE=0
LLM_DISABLE_PROXY=1
LLM_VERIFY_SSL=1
```

未配置 LLM 时，Agent D 会自动进入 rule fallback 模式，仍可完成可复现的七 Agent 链路。

## 7. 当前边界

- Agent B 是轻量启发式切片器，不是完整 Clang AST/CFG/Joern 级切片器。
- Agent E 生成的 Harness 对样例项目效果较好；真实大型项目可能还需要适配构建参数、头文件路径和初始化逻辑。
- ASan 已形成可复现动态验证证据；AFL++/eBPF 更适合作为后续动态增强方向。
- 后端与前端已有主体代码，但仍需要按接口契约继续打磨联调。

## 8. 推荐演示顺序

```text
1. 展示七 Agent 链路
2. 运行 sentinel_agent/main.py
3. 展示 Agent A 的 components_rich 和风险画像
4. 展示 Agent B 的 semantic slices、risk_score、dataflow_hints
5. 展示 Agent C 的 hypotheses
6. 展示 Agent D 的 static_findings 和 quality_summary
7. 展示 Agent E 的 Harness 包和质量门控
8. 展示 Agent F 的 evidence_links
9. 展示 Agent G 的 final_report.md
10. 启动 service.py，说明后端可关闭 Mock 调用真实 ML 服务
```

