# Part 6：交付检查清单

## 必须存在的核心输出

```text
outputs/final_report.md
outputs/final_report.json
outputs/agent_a_components.json
outputs/agent_b_slices.json
outputs/agent_c_findings.json
outputs/agent_d_harness_packages.json
validation/asan_validation_results.json
```

## 必须存在的 ASan 日志

```text
harness_packages/HARNESS-0001/asan_double_free.log
harness_packages/HARNESS-0002/asan_heap.log
harness_packages/HARNESS-0003/asan_stack.log
harness_packages/HARNESS-0004/asan_uaf.log
```

## final_report.md 中必须出现

```text
ASan Confirmed Findings: 4
ASan Bug Type: `double-free`
ASan Bug Type: `heap-buffer-overflow`
ASan Bug Type: `stack-buffer-overflow`
ASan Bug Type: `heap-use-after-free`
```

## main.py 最终输出必须出现

```text
Components: 6
Static Findings: 4
Harness Packages: 4
Confirmed Findings: 4
ASan Confirmed Findings: 4
```
