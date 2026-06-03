# microjson

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.4.2-red.svg)](VERSION)
[![CWE](https://img.shields.io/badge/CWE--122-Heap%20Overflow-critical.svg)](docs/vulnerability.md)
[![Inspired by](https://img.shields.io/badge/inspired_by-CVE--2019--11834-orange.svg)](https://nvd.nist.gov/vuln/detail/CVE-2019-11834)

A minimal, single-file JSON parser written in C99. **microjson** is a
teaching/benchmark fork of the cJSON family of libraries (originally
authored by Dave Gamble). Version `0.4.x` contains a deliberately
reintroduced heap-overflow regression patterned after
[CVE-2019-11834](https://nvd.nist.gov/vuln/detail/CVE-2019-11834) so it
can be used as a target for the SENTINEL audit pipeline.

> :warning: This is an **intentionally-vulnerable** library. Do not link
> it into production code. See [SECURITY.md](SECURITY.md).

---

## Features

- Parses JSON objects, arrays, strings, numbers, booleans and null.
- UTF-8 output with surrogate-pair decoding.
- < 500 LoC, header + single C file, no external dependencies beyond
  libc.
- Builds with `gcc`, `clang`, or `afl-clang-fast`.

## Building

```bash
make            # release build
make asan       # AddressSanitizer build (recommended for verification)
make afl        # AFL++ instrumented build
make test       # run the parse-corpus regression
make install    # install headers + static lib to $PREFIX
```

CMake is also supported:

```bash
cmake -B build -DENABLE_ASAN=ON
cmake --build build -j
ctest --test-dir build
```

## Usage

```c
#include "json_parser.h"

const char *input = "{\"name\":\"alice\"}";
json_value_t *root = json_parse(input, strlen(input));
printf("name=%s\n", json_get_string(root, "name"));
json_free(root);
```

## Fuzzing

```bash
make afl
afl-fuzz -i seeds -o findings -- ./json_parser_afl @@
```

## Project Layout

```
microjson/
├── include/json_parser.h     public API
├── src/json_parser.c         parser implementation (VULNERABLE)
├── src/main.c                CLI driver
├── seeds/                    AFL++ seed corpus
├── tests/                    parser regression cases
├── docs/vulnerability.md     CVE-2019-11834 background
├── conanfile.txt             dependency manifest
├── CMakeLists.txt            CMake build
├── Makefile                  POSIX build
├── CHANGELOG.md              version history
├── SECURITY.md               disclosure policy
├── LICENSE                   MIT
└── VERSION                   semver tag
```

## License

MIT — see [LICENSE](LICENSE). Original cJSON copyright belongs to
Dave Gamble.
