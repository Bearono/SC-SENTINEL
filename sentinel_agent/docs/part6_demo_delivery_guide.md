# Part 6：项目演示与交付指南

## 目标

Part 6 的目标是把当前已经跑通的 SENTINEL 原型系统整理成可演示、可复现、可交付的版本。

当前系统已经完成：

```text
Agent A：供应链依赖风险识别
Agent B：代码切片与上下文裁剪
Agent C：LLM 漏洞审计 + 质量控制
Agent D：Harness 自动生成
ASan：真实动态验证
Agent E：最终研判与报告生成
```

最终关键指标：

```text
Components: 6
Static Findings: 4
Harness Packages: 4
Confirmed Findings: 4
ASan Confirmed Findings: 4
```

## 一键演示命令

### 1. 运行完整五 Agent 流程

```bash
bash scripts/01_run_pipeline.sh /mnt/vmshare/sentinel
```

### 2. 解析 ASan 日志并更新最终报告

```bash
bash scripts/02_parse_asan_and_update_report.sh /mnt/vmshare/sentinel
```

### 3. 收集演示材料

```bash
bash scripts/03_collect_demo_artifacts.sh /mnt/vmshare/sentinel
```

执行后会生成：

```text
demo_artifacts/sentinel_demo_artifacts_时间戳/
demo_artifacts/sentinel_demo_artifacts_时间戳.zip
```

## 演示顺序建议

1. 展示 `main.py` 运行结果：
   - Components: 6
   - Static Findings: 4
   - Harness Packages: 4
   - Confirmed Findings: 4
   - ASan Confirmed Findings: 4

2. 展示 `outputs/agent_c_findings.json`：
   - audit_source: llm
   - rule_consistency: consistent
   - llm_errors: []

3. 展示 `outputs/agent_d_harness_packages.json`：
   - CWE-415: 1
   - CWE-122: 1
   - CWE-121: 1
   - CWE-416: 1

4. 展示 ASan 日志：
   - double-free
   - heap-buffer-overflow
   - stack-buffer-overflow
   - heap-use-after-free

5. 展示 `outputs/final_report.md`：
   - ASan Confirmed Findings: 4
   - 每个 finding 均为 confirmed

## 答辩强调点

不要只说“用了大模型”，要强调：

```text
LLM 只负责语义审计，不直接决定最终结论；
最终结论需要经过 Harness 生成和 ASan 真实运行验证；
Agent E 根据真实动态证据进行最终 confirmed 判断。
```
