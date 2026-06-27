# SENTINEL Harness Package

## Finding

- Finding ID: `FINDING-0003`
- Target file: `src\main.c`
- Target function: `main`
- CWE: `CWE-415`
- Vulnerability type: `Double Free`
- Line range: `[36, 45]`

## Trigger condition

Pointer 'buf' is freed more than once without reset or reallocation.

## Strategy

- Strategy name: `original_main_file_replay`
- Argument model: `original_main_file_arg`
- Expected sanitizer: `AddressSanitizer`
- Expected symptom: `double-free`

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
