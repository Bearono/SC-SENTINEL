# SENTINEL Harness Package

## Finding

- Finding ID: `FINDING-0016`
- Target file: `uaf_cross_function.c`
- Target function: `edit_chunk`
- CWE: `CWE-122`
- Vulnerability type: `Possible Buffer Overflow`
- Line range: `[18, 18]`

## Trigger condition

Oversized or attacker-controlled input may reach a copy operation without sufficient length validation.

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
