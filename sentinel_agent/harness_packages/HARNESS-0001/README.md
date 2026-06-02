# SENTINEL Harness Package

## Finding

- Finding ID: `FINDING-0001`
- Target file: `double_free_demo.c`
- Target function: `double_free_case`
- CWE: `CWE-415`
- Vulnerability type: `Double Free`
- Line range: `[8, 11]`

## Trigger condition

Execution reaches free(buf) twice without reset or reallocation.

## Strategy

- Strategy name: `flag_path_trigger`
- Argument model: `int_flag`
- Expected sanitizer: `AddressSanitizer`
- Expected symptom: `double-free or heap-use-after-free`

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
