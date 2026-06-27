# SENTINEL Harness Package

## Finding

- Finding ID: `FINDING-0019`
- Target file: `format_string_fprintf.c`
- Target function: `log_event`
- CWE: `CWE-134`
- Vulnerability type: `Format String Vulnerability`
- Line range: `[3, 3]`

## Trigger condition

A printf-style function appears to use a non-literal format argument.

## Strategy

- Strategy name: `format_string_payload`
- Argument model: `const_char_ptr`
- Expected sanitizer: `AddressSanitizer`
- Expected symptom: `format string memory disclosure or write via %n`

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
