# astlite

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.2.0-red.svg)](VERSION)
[![CWE](https://img.shields.io/badge/CWE--415-Double%20Free-critical.svg)](docs/vulnerability.md)
[![Inspired by](https://img.shields.io/badge/inspired_by-cJSON%20%23833-orange.svg)](https://github.com/DaveGamble/cJSON/issues/833)

A minimal AST (Abstract Syntax Tree) node allocator and serializer in
C99. `astlite` 0.2.x retains a deliberately reintroduced double-free
regression patterned after the cJSON shared-child issue
([#833](https://github.com/DaveGamble/cJSON/issues/833)) for use as a
SENTINEL benchmark target.

> :warning: Intentionally-vulnerable code — do not embed in a real
> compiler or parser frontend.

## Building

```bash
make
make asan
make afl
make test
```

## Usage

```bash
./ast_demo seeds/seed_01.txt
```

## Dependencies

None — `astlite` is self-contained.

## License

MIT — see [LICENSE](LICENSE).
