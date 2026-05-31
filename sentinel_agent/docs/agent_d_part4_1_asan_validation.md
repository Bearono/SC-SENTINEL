
# Agent D Part 4.1: Actual ASan Harness Validation

## Fix

The Part 4 Makefile used:

```makefile
-Dmain=sentinel_original_main
```

on both target source and harness source. This may rename the harness `main()` and cause:

```text
undefined reference to main
```

Part 4.1 fixes this by compiling separately:

```text
target source  -> with -Dmain=sentinel_original_main
harness source -> without -Dmain
```

## Test in WSL2

Example:

```bash
cd /mnt/d/sentinel/harness_packages/HARNESS-0001
make clean
make asan
make run-asan
```

Expected sanitizer examples:

```text
AddressSanitizer: attempting double-free
AddressSanitizer: heap-buffer-overflow
AddressSanitizer: stack-buffer-overflow
AddressSanitizer: heap-use-after-free
```
