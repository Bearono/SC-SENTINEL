# SENTINEL 运行说明

本文档说明如何从零开始运行当前 SENTINEL 项目，并复现最终结果。

## 1. 进入项目目录

```bash
cd /mnt/vmshare/sentinel
```

确认目录结构：

```bash
ls
```

应能看到：

```text
agents  core  cve  samples  harness_packages  outputs  validation  tools  scripts  main.py
```

## 2. 安装系统依赖

```bash
sudo apt update
sudo apt install -y build-essential clang make unzip zip
```

## 3. 安装 Python 依赖

```bash
pip install -r requirements.txt
```

## 4. 检查 LLM 配置

如果使用 LLM 审计，需要配置 `.env`：

```bash
cat .env
```

应包含：

```text
LLM_API_KEY=...
LLM_BASE_URL=...
LLM_MODEL=...
```

可测试连接：

```bash
python3 tools/test_llm_connection.py
```

如果连接正常，Agent C 会以 LLM 模式运行；如果连接失败，系统会自动回退到规则检测。

## 5. 运行完整五 Agent 流程

```bash
bash scripts/01_run_pipeline.sh /mnt/vmshare/sentinel
```

预期关键输出：

```text
Components: 6
Static Findings: 4
Harness Packages: 4
Confirmed Findings: 4
ASan Confirmed Findings: 4
```

## 6. 手动运行主程序

```bash
python3 main.py --project ./samples/vulnerable_project
```

## 7. 检查 ASan 日志

```bash
find harness_packages -name "*.log" -type f
```

应看到：

```text
harness_packages/HARNESS-0001/asan_double_free.log
harness_packages/HARNESS-0002/asan_heap.log
harness_packages/HARNESS-0003/asan_stack.log
harness_packages/HARNESS-0004/asan_uaf.log
```

## 8. 重新解析 ASan 日志

```bash
python3 tools/parse_asan_logs.py \
  --harness-root harness_packages \
  --output validation/asan_validation_results.json
```

预期输出：

```text
Total logs: 4
Confirmed findings: 4
Failed or unconfirmed: 0
```

## 9. 更新最终报告

```bash
python3 main.py --project ./samples/vulnerable_project
```

或直接运行：

```bash
bash scripts/02_parse_asan_and_update_report.sh /mnt/vmshare/sentinel
```

## 10. 查看最终报告

```bash
cat outputs/final_report.md
```

查看 ASan 相关结论：

```bash
grep -n "ASan" outputs/final_report.md
```

预期包括：

```text
ASan Confirmed Findings: 4
ASan Bug Type: `double-free`
ASan Bug Type: `heap-buffer-overflow`
ASan Bug Type: `stack-buffer-overflow`
ASan Bug Type: `heap-use-after-free`
```

## 11. 收集演示材料

```bash
bash scripts/03_collect_demo_artifacts.sh /mnt/vmshare/sentinel
```

生成：

```text
demo_artifacts/sentinel_demo_artifacts_时间戳.zip
```

## 12. 常见问题

### 问题 1：`scripts/*.sh` 不存在

说明 Part 6 补丁没有解压到项目根目录。请确认：

```bash
ls scripts
```

如果不存在，需要重新解压 Part 6 补丁。

### 问题 2：`ASan Confirmed Findings` 不是 4

先检查日志是否齐全：

```bash
find harness_packages -name "*.log" -type f
```

如果日志少于 4 个，需要重新运行对应 Harness 并用 `tee` 保存日志。

### 问题 3：ASan 日志存在但解析结果不匹配

重新运行：

```bash
python3 tools/parse_asan_logs.py \
  --harness-root harness_packages \
  --output validation/asan_validation_results.json
```

再运行：

```bash
python3 main.py --project ./samples/vulnerable_project
```

### 问题 4：LLM 调用失败

检查：

```bash
cat .env
python3 tools/test_llm_connection.py
```

如果暂时无法使用 LLM，系统仍可 fallback 运行，但答辩展示建议使用已经成功生成的结果包。
