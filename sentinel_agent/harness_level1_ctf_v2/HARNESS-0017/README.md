# SENTINEL Harness Package

## Finding

- Finding ID: `FINDING-0017`
- Target file: `uaf_direct.c`
- Target function: `run_note_machine`
- CWE: `CWE-416`
- Vulnerability type: `Use After Free`
- Line range: `[17, 20]`

## Trigger condition

Pointer 'note' is dereferenced or accessed after free.

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
