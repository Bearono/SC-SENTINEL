# SENTINEL Harness Package

## Finding

- Finding ID: `FINDING-0002`
- Target file: `src\png_loader.c`
- Target function: `png_process_chunk`
- CWE: `CWE-122`
- Vulnerability type: `Possible Buffer Overflow`
- Line range: `[200, 200]`

## Trigger condition

Dangerous copy-style operation may write beyond destination bounds.

## Strategy

- Strategy name: `original_main_file_replay`
- Argument model: `original_main_file_arg`
- Expected sanitizer: `AddressSanitizer`
- Expected symptom: `heap-buffer-overflow`

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
