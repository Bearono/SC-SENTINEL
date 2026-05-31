# SENTINEL Harness Package

## Finding

- Finding ID: `FINDING-0003`
- Target file: `stack_overflow_demo.c`
- Target function: `stack_overflow_case`
- CWE: `CWE-121`
- Vulnerability type: `Stack Buffer Overflow`
- Line range: `[3, 4]`

## Trigger condition

当输入参数 input 的字符串长度大于等于 8 字节（含空终止符）时

## Strategy

- Strategy name: `oversized_string_input`
- Argument model: `const_char_ptr`
- Expected sanitizer: `AddressSanitizer`
- Expected symptom: `heap-buffer-overflow or stack-buffer-overflow`

## Commands in WSL2 / Docker

```bash
make clean
make asan
make run-asan
```

Optional:

```bash
make afl
make run-afl
```

```bash
make libfuzzer
./libfuzzer_target seeds
```

## Notes

Part 4.1 compiles the target source and harness separately.
Only the target source receives `-Dmain=sentinel_original_main`, so the harness main function remains valid.
