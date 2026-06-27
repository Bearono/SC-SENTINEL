# SENTINEL Harness Package

## Finding

- Finding ID: `FINDING-0006`
- Target file: `heap_overflow_integer_trunc.c`
- Target function: `resize_then_write`
- CWE: `CWE-122`
- Vulnerability type: `Heap Buffer Overflow`
- Line range: `[10, 10]`

## Trigger condition

Dangerous copy-style operation may write beyond destination bounds.

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
