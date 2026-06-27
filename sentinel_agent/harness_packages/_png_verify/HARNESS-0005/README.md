# SENTINEL Harness Package

## Finding

- Finding ID: `FINDING-0005`
- Target file: `src\main.c`
- Target function: `main`
- CWE: `CWE-416`
- Vulnerability type: `Use After Free`
- Line range: `[36, 40]`

## Trigger condition

Expression 'buf' is freed and later used through 'png_load'.

## Strategy

- Strategy name: `original_main_file_replay`
- Argument model: `original_main_file_arg`
- Expected sanitizer: `AddressSanitizer`
- Expected symptom: `heap-use-after-free`

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
