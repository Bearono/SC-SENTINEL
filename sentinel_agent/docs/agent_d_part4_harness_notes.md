
# Agent D Part 4: Harness Generation

## Goal

Upgrade Agent D from a generic template generator to a CWE-aware harness generator.

## Generated files per finding

Each harness package contains:

```text
HARNESS-0001/
├── afl_harness.c
├── libfuzzer_harness.c
├── Makefile
├── README.md
├── harness_config.json
└── seeds/
    ├── seed_001.bin
    ├── seed_002_*.bin
    └── seed_003_*.bin
```

## CWE-specific strategies

| CWE | Strategy | Argument model |
|---|---|---|
| CWE-416 | flag_path_trigger | int flag |
| CWE-415 | flag_path_trigger | int flag |
| CWE-122 | oversized_string_input | const char *input |
| CWE-121 | oversized_string_input | const char *input |

## Build commands

In WSL2 / Docker:

```bash
make asan
make run-asan
```

```bash
make afl
make run-afl
```

```bash
make libfuzzer
./libfuzzer_target seeds
```

## Important limitation

The generated harness is close to usable for the sample project.
For real C/C++ projects, manual adaptation is often needed because:

- function signatures vary
- source files may require include paths
- project initialization may be needed
- build systems may require CMake/Make integration
