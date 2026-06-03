
from pathlib import Path
from core.id_generator import make_id
from core.json_utils import save_json

# Agent D - Harness Automatic Generation
#
# Part 4.1 upgraded version:
# - Keeps Part 4 CWE-aware harness generation.
# - Fixes Makefile compilation issue:
#   The old Makefile passed -Dmain=sentinel_original_main to both harness and target source.
#   That could rename the harness's own main() and cause "undefined reference to main".
# - New Makefile compiles:
#   1. target source with -Dmain=sentinel_original_main
#   2. harness source without -Dmain=...
#   3. links both object files into ASan/AFL++/libFuzzer targets.


def run_agent_d(agent_c_result, harness_root="harness_packages", project_root=None):
    harness_root = Path(harness_root)
    harness_root.mkdir(parents=True, exist_ok=True)
    project_root = Path(project_root).resolve() if project_root else None

    packages = []
    for idx, finding in enumerate(agent_c_result.get("static_findings", []), start=1):
        package_id = make_id("HARNESS", idx)
        package_dir = harness_root / package_id
        seeds_dir = package_dir / "seeds"
        crashes_dir = package_dir / "findings"
        seeds_dir.mkdir(parents=True, exist_ok=True)
        crashes_dir.mkdir(parents=True, exist_ok=True)

        strategy = infer_harness_strategy(finding)

        (package_dir / "afl_harness.c").write_text(
            make_afl_harness(finding, strategy),
            encoding="utf-8"
        )
        (package_dir / "libfuzzer_harness.c").write_text(
            make_libfuzzer_harness(finding, strategy),
            encoding="utf-8"
        )
        (package_dir / "Makefile").write_text(
            make_makefile(finding, strategy, project_root),
            encoding="utf-8"
        )
        (package_dir / "README.md").write_text(
            make_readme(finding, strategy),
            encoding="utf-8"
        )

        seed_files = write_seed_files(seeds_dir, finding, strategy)

        package = {
            "package_id": package_id,
            "finding_id": finding["finding_id"],
            "target_file": finding["file"],
            "target_function": finding["function"],
            "cwe_id": finding["cwe_id"],
            "vulnerability_type": finding["vulnerability_type"],
            "risk_level": finding.get("risk_level", "unknown"),
            "line_range": finding.get("line_range"),
            "trigger_condition": finding.get("trigger_condition", ""),
            "strategy": strategy,
            "package_dir": str(package_dir),
            "afl_harness_file": str(package_dir / "afl_harness.c"),
            "libfuzzer_harness_file": str(package_dir / "libfuzzer_harness.c"),
            "makefile": str(package_dir / "Makefile"),
            "seed_dir": str(seeds_dir),
            "seed_files": seed_files,
            "asan_build_command": "make asan",
            "afl_build_command": "make afl",
            "libfuzzer_build_command": "make libfuzzer",
            "asan_run_command": "./asan_target seeds/seed_001.bin",
            "afl_run_command": "afl-fuzz -i seeds -o findings -- ./afl_target @@",
            "notes": (
                "Part 4.1 generated harness package. "
                "The target source and harness are compiled separately so -Dmain only affects the target source."
            )
        }

        save_json(package, package_dir / "harness_config.json")
        packages.append(package)

    return {
        "agent": "Agent D - Harness Automatic Generation",
        "harness_packages": packages,
        "summary": {
            "total_packages": len(packages),
            "packages_by_cwe": count_by_cwe(packages)
        }
    }


def infer_harness_strategy(finding):
    cwe = finding.get("cwe_id")

    if cwe in {"CWE-416", "CWE-415"}:
        return {
            "strategy_name": "flag_path_trigger",
            "argument_model": "int_flag",
            "trigger_value": 1,
            "description": (
                "Call the target function with flag=1 to force the vulnerable branch, "
                "such as double free or use-after-free path."
            ),
            "expected_sanitizer": "AddressSanitizer",
            "expected_symptom": "double-free or heap-use-after-free"
        }

    if cwe in {"CWE-122", "CWE-121"}:
        return {
            "strategy_name": "oversized_string_input",
            "argument_model": "const_char_ptr",
            "min_input_size": 256,
            "description": (
                "Read fuzzer-controlled bytes, ensure null termination, and pass them as "
                "a string argument to trigger unsafe copy operations."
            ),
            "expected_sanitizer": "AddressSanitizer",
            "expected_symptom": "heap-buffer-overflow or stack-buffer-overflow"
        }

    if cwe == "CWE-134":
        return {
            "strategy_name": "format_string_payload",
            "argument_model": "const_char_ptr",
            "min_input_size": 32,
            "description": (
                "Pass fuzzer-controlled bytes as a format string payload. Seeds include "
                "%x/%p/%s/%n patterns that can expose or corrupt memory when the target "
                "uses attacker input as the format argument."
            ),
            "expected_sanitizer": "AddressSanitizer",
            "expected_symptom": "format string memory disclosure or write via %n"
        }

    return {
        "strategy_name": "generic_file_input",
        "argument_model": "manual_adaptation_required",
        "description": "Generic template. Manual adaptation is needed.",
        "expected_sanitizer": "AddressSanitizer",
        "expected_symptom": "memory safety violation"
    }


def make_afl_harness(finding, strategy):
    cwe = finding.get("cwe_id")
    function = finding.get("function")
    file = finding.get("file")
    signature = infer_function_prototype(finding, strategy)
    call_code = make_target_call_for_afl(function, strategy)

    return f"""
/*
 * SENTINEL Agent D - AFL++ / ASan file-input harness
 *
 * Finding ID: {finding.get("finding_id")}
 * Target file: {file}
 * Target function: {function}
 * CWE: {cwe}
 * Strategy: {strategy.get("strategy_name")}
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

{signature}

static unsigned char *read_file(const char *path, size_t *out_size) {{
    FILE *fp = fopen(path, "rb");
    if (!fp) {{
        return NULL;
    }}

    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (size < 0) {{
        fclose(fp);
        return NULL;
    }}

    unsigned char *buf = (unsigned char *)malloc((size_t)size + 1);
    if (!buf) {{
        fclose(fp);
        return NULL;
    }}

    size_t n = fread(buf, 1, (size_t)size, fp);
    fclose(fp);

    buf[n] = '\\0';
    *out_size = n;
    return buf;
}}

int main(int argc, char **argv) {{
    if (argc < 2) {{
        return 0;
    }}

    size_t size = 0;
    unsigned char *data = read_file(argv[1], &size);
    if (!data) {{
        return 0;
    }}

{indent(call_code, 4)}

    free(data);
    return 0;
}}
""".strip() + "\n"


def make_libfuzzer_harness(finding, strategy):
    cwe = finding.get("cwe_id")
    function = finding.get("function")
    file = finding.get("file")
    signature = infer_function_prototype(finding, strategy)
    call_code = make_target_call_for_libfuzzer(function, strategy)

    return f"""
/*
 * SENTINEL Agent D - libFuzzer-style harness
 *
 * Finding ID: {finding.get("finding_id")}
 * Target file: {file}
 * Target function: {function}
 * CWE: {cwe}
 * Strategy: {strategy.get("strategy_name")}
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

{signature}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {{
    if (Data == NULL) {{
        return 0;
    }}

{indent(call_code, 4)}

    return 0;
}}
""".strip() + "\n"


def infer_function_prototype(finding, strategy):
    function = finding.get("function")
    argument_model = strategy.get("argument_model")

    if argument_model == "int_flag":
        return f"void {function}(int flag);"

    if argument_model == "const_char_ptr":
        return f"void {function}(const char *input);"

    return f"/* TODO: declare the real target function prototype for {function}. */"


def make_target_call_for_afl(function, strategy):
    argument_model = strategy.get("argument_model")

    if argument_model == "int_flag":
        return f"""
/*
 * For UAF / Double Free demos, flag=1 triggers the vulnerable branch.
 */
{function}(1);
""".strip()

    if argument_model == "const_char_ptr":
        return f"""
/*
 * data is null-terminated by read_file().
 * Passing it as a string can trigger unsafe strcpy/memcpy-style code.
 */
if (size > 0) {{
    {function}((const char *)data);
}}
""".strip()

    return f"""
/*
 * TODO: Convert data/size into parameters for {function}.
 */
(void)data;
(void)size;
""".strip()


def make_target_call_for_libfuzzer(function, strategy):
    argument_model = strategy.get("argument_model")

    if argument_model == "int_flag":
        return f"""
/*
 * Non-zero input triggers the vulnerable flag branch.
 */
int flag = (Size > 0 && Data[0] != 0) ? 1 : 0;
{function}(flag);
""".strip()

    if argument_model == "const_char_ptr":
        return f"""
/*
 * Make a null-terminated string from fuzzer bytes.
 */
char *buf = (char *)malloc(Size + 1);
if (!buf) {{
    return 0;
}}
memcpy(buf, Data, Size);
buf[Size] = '\\0';

{function}((const char *)buf);

free(buf);
""".strip()

    return f"""
/*
 * TODO: Convert Data/Size into parameters for {function}.
 */
(void)Data;
(void)Size;
""".strip()


def make_makefile(finding, strategy, project_root=None):
    target_file = finding.get("file")
    if project_root:
        target_src = str((project_root / target_file).resolve()).replace("\\", "/")
    else:
        target_src = f"../../samples/vulnerable_project/{target_file}"

    return f"""
# SENTINEL Agent D generated Makefile - Part 4.1
#
# This Makefile fixes the -Dmain problem:
# - target source is compiled with -Dmain=sentinel_original_main
# - harness source is compiled without -Dmain
#
# Linux / WSL2 / Docker recommended.

TARGET_SRC ?= {target_src}
CC ?= clang
AFL_CC ?= afl-clang

COMMON_FLAGS ?= -g -O1 -fsanitize=address -fno-omit-frame-pointer
TARGET_RENAME_MAIN ?= -Dmain=sentinel_original_main

.PHONY: all asan afl libfuzzer clean run-asan run-afl

all: asan

target_asan.o:
\t$(CC) $(COMMON_FLAGS) $(TARGET_RENAME_MAIN) -c $(TARGET_SRC) -o target_asan.o

harness_asan.o:
\t$(CC) $(COMMON_FLAGS) -c afl_harness.c -o harness_asan.o

asan: target_asan.o harness_asan.o
\t$(CC) $(COMMON_FLAGS) harness_asan.o target_asan.o -o asan_target

target_afl.o:
\t$(AFL_CC) $(COMMON_FLAGS) $(TARGET_RENAME_MAIN) -c $(TARGET_SRC) -o target_afl.o

harness_afl.o:
\t$(AFL_CC) $(COMMON_FLAGS) -c afl_harness.c -o harness_afl.o

afl: target_afl.o harness_afl.o
\t$(AFL_CC) $(COMMON_FLAGS) harness_afl.o target_afl.o -o afl_target

target_libfuzzer.o:
\t$(CC) -g -O1 -fsanitize=fuzzer-no-link,address $(TARGET_RENAME_MAIN) -c $(TARGET_SRC) -o target_libfuzzer.o

harness_libfuzzer.o:
\t$(CC) -g -O1 -fsanitize=fuzzer-no-link,address -c libfuzzer_harness.c -o harness_libfuzzer.o

libfuzzer: target_libfuzzer.o harness_libfuzzer.o
\t$(CC) -g -O1 -fsanitize=fuzzer,address harness_libfuzzer.o target_libfuzzer.o -o libfuzzer_target

run-asan: asan
\t./asan_target seeds/seed_001.bin

run-afl: afl
\tafl-fuzz -i seeds -o findings -- ./afl_target @@

clean:
\trm -f *.o asan_target afl_target libfuzzer_target
\trm -rf findings/default findings/*/queue findings/*/crashes findings/*/hangs
""".strip() + "\n"


def write_seed_files(seeds_dir, finding, strategy):
    cwe = finding.get("cwe_id")

    if cwe in {"CWE-122", "CWE-121"}:
        seeds = {
            "seed_001.bin": b"A" * 256,
            "seed_002_long_string.bin": b"B" * 1024,
            "seed_003_pattern.bin": (b"0123456789abcdef" * 32)
        }
    elif cwe == "CWE-134":
        seeds = {
            "seed_001.bin": b"%x.%x.%x.%x",
            "seed_002_pointer_leak.bin": b"%p %p %p %p",
            "seed_003_write_probe.bin": b"%n%n%n%n"
        }
    elif cwe in {"CWE-416", "CWE-415"}:
        seeds = {
            "seed_001.bin": b"\x01",
            "seed_002_trigger_flag.bin": b"trigger=1",
            "seed_003_nonzero.bin": b"\xff"
        }
    else:
        seeds = {
            "seed_001.bin": b"default_seed"
        }

    seed_files = []
    for name, content in seeds.items():
        path = seeds_dir / name
        path.write_bytes(content)
        seed_files.append(str(path))

    return seed_files


def make_readme(finding, strategy):
    return f"""
# SENTINEL Harness Package

## Finding

- Finding ID: `{finding.get("finding_id")}`
- Target file: `{finding.get("file")}`
- Target function: `{finding.get("function")}`
- CWE: `{finding.get("cwe_id")}`
- Vulnerability type: `{finding.get("vulnerability_type")}`
- Line range: `{finding.get("line_range")}`

## Trigger condition

{finding.get("trigger_condition", "")}

## Strategy

- Strategy name: `{strategy.get("strategy_name")}`
- Argument model: `{strategy.get("argument_model")}`
- Expected sanitizer: `{strategy.get("expected_sanitizer")}`
- Expected symptom: `{strategy.get("expected_symptom")}`

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
""".strip() + "\n"


def count_by_cwe(packages):
    result = {}
    for pkg in packages:
        cwe = pkg.get("cwe_id", "UNKNOWN")
        result[cwe] = result.get(cwe, 0) + 1
    return result


def indent(text, spaces):
    prefix = " " * spaces
    return "\n".join(prefix + line if line.strip() else line for line in text.splitlines())
