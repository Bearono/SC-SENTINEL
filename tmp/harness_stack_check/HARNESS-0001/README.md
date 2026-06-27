# SENTINEL Harness Package

## Finding

- Finding ID: `FINDING-TEST`
- Target file: `stack_overflow_loop.c`
- Target function: `copy_loop`
- CWE: `CWE-121`
- Vulnerability type: `Stack Buffer Overflow`
- Line range: `[5, 5]`

## Trigger condition

Stack array dst[10] is written with an index that is not locally bounded.

## Strategy

- Strategy name: `original_main_file_replay`
- Argument model: `original_main_file_arg`
- Expected sanitizer: `AddressSanitizer`
- Expected symptom: `stack-buffer-overflow`

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
