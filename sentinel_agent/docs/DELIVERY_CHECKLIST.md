# SENTINEL 最终交付检查清单

## 1. 主流程输出检查

运行：

```bash
bash scripts/01_run_pipeline.sh /mnt/vmshare/sentinel
```

必须看到：

```text
Components: 6
Static Findings: 4
Harness Packages: 4
Confirmed Findings: 4
ASan Confirmed Findings: 4
```

## 2. ASan 日志检查

运行：

```bash
find harness_packages -name "*.log" -type f
```

必须包含：

```text
harness_packages/HARNESS-0001/asan_double_free.log
harness_packages/HARNESS-0002/asan_heap.log
harness_packages/HARNESS-0003/asan_stack.log
harness_packages/HARNESS-0004/asan_uaf.log
```

## 3. ASan 解析结果检查

运行：

```bash
python3 tools/parse_asan_logs.py \
  --harness-root harness_packages \
  --output validation/asan_validation_results.json
```

必须看到：

```text
Total logs: 4
Confirmed findings: 4
Failed or unconfirmed: 0
```

## 4. 最终报告检查

运行：

```bash
grep -n "ASan" outputs/final_report.md
```

必须看到：

```text
ASan Confirmed Findings: 4
ASan Bug Type: `double-free`
ASan Consistency: `matched_expected_cwe`
ASan Bug Type: `heap-buffer-overflow`
ASan Consistency: `matched_expected_cwe`
ASan Bug Type: `stack-buffer-overflow`
ASan Consistency: `matched_expected_cwe`
ASan Bug Type: `heap-use-after-free`
ASan Consistency: `matched_expected_cwe`
```

## 5. 演示材料包检查

运行：

```bash
bash scripts/03_collect_demo_artifacts.sh /mnt/vmshare/sentinel
```

必须生成：

```text
demo_artifacts/sentinel_demo_artifacts_时间戳.zip
```

压缩包中应包含：

```text
outputs/
validation/
asan_logs/
docs/
SUMMARY.json
SUMMARY.md
```

## 6. 建议提交材料

建议提交以下内容：

```text
1. 完整项目代码压缩包
2. demo_artifacts/sentinel_demo_artifacts_时间戳.zip
3. outputs/final_report.md
4. validation/asan_validation_results.json
5. 四个 ASan 原始日志
6. 项目答辩 PPT
```

## 7. 答辩展示优先级

展示优先级如下：

```text
1. final_report.md 中 ASan Confirmed Findings: 4
2. 四个 ASan Bug Type 与 CWE 匹配
3. Agent C 的 LLM finding 和 rule_consistency
4. Agent D 的 harness package summary
5. Agent A 的 6 个组件识别结果
```
