# Part 4.2: Connect Real ASan Results to Agent E

## Goal

Replace mock dynamic evidence with real AddressSanitizer validation logs.

## New parser

```bash
python3 tools/parse_asan_logs.py --harness-root harness_packages --output validation/asan_validation_results.json
```

## Required log files

Recommended names:

```text
harness_packages/HARNESS-0001/asan_double_free.log
harness_packages/HARNESS-0002/asan_heap.log
harness_packages/HARNESS-0003/asan_stack.log
harness_packages/HARNESS-0004/asan_uaf.log
```

The parser scans `*.log` under every `HARNESS-*` directory.

## Expected final summary

```text
ASan Confirmed Findings: 4
Confirmed Findings: 4
```
