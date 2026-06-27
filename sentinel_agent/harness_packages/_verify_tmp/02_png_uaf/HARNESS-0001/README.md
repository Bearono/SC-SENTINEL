# SENTINEL Harness Package

## Finding

- Finding ID: `FINDING-0001`
- Target file: `src\png_loader.c`
- Target function: `png_fire_callbacks`
- CWE: `CWE-416`
- Vulnerability type: `Use After Free`
- Line range: `[132, 132]`

## Trigger condition

Stored callback context pointers are dereferenced during callback dispatch, which is a classic trigger site for a dangling-pointer UAF.

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
