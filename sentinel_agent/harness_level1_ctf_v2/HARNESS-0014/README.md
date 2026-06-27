# SENTINEL Harness Package

## Finding

- Finding ID: `FINDING-0014`
- Target file: `stack_overflow_strcpy.c`
- Target function: `set_player_name`
- CWE: `CWE-121`
- Vulnerability type: `Stack Buffer Overflow`
- Line range: `[4, 4]`

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
