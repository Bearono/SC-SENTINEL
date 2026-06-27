# SENTINEL Harness Package

## Finding

- Finding ID: `FINDING-0027`
- Target file: `double_free_direct.c`
- Target function: `main`
- CWE: `CWE-415`
- Vulnerability type: `Double Free`
- Line range: `[19, 21]`

## Trigger condition

Memory expression 'note' is freed after an equivalent expression was already freed.

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
