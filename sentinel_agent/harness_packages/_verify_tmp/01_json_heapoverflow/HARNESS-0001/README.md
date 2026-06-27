# SENTINEL Harness Package

## Finding

- Finding ID: `FINDING-0001`
- Target file: `src\json_parser.c`
- Target function: `json_parse_string`
- CWE: `CWE-122`
- Vulnerability type: `Heap Buffer Overflow`
- Line range: `[123, 136]`

## Trigger condition

Heap buffer 'buf' is allocated from a derived size and then written through a growing offset without a visible bounds check.

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
