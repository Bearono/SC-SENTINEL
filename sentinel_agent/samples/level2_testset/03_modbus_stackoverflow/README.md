# modlite

[![License](https://img.shields.io/badge/license-LGPL--2.1-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-3.1.6-red.svg)](VERSION)
[![CWE](https://img.shields.io/badge/CWE--121-Stack%20Overflow-critical.svg)](docs/vulnerability.md)
[![Inspired by](https://img.shields.io/badge/inspired_by-CVE--2022--0367-orange.svg)](https://nvd.nist.gov/vuln/detail/CVE-2022-0367)

A minimal Modbus TCP request/response parser, derived from a stripped
fork of `libmodbus`. The 3.1.x line of `modlite` retains a deliberate
stack-buffer-overflow regression patterned after
[CVE-2022-0367](https://nvd.nist.gov/vuln/detail/CVE-2022-0367) and
[CVE-2024-10918](https://nvd.nist.gov/vuln/detail/CVE-2024-10918) for
SENTINEL benchmarking.

> :warning: Intentionally-vulnerable code — do not deploy on any
> control-system network.

## Building

```bash
make            # release
make asan       # AddressSanitizer build
make afl        # AFL++ instrumentation
make test       # smoke run with the seed corpus
```

## Usage

```bash
./modbus_parser seeds/seed_01.bin
```

## Dependencies

`modlite` has no runtime dependencies outside libc. The optional TLS
extension links against OpenSSL when `MODLITE_TLS=1` is set.

## License

LGPL-2.1 — see [LICENSE](LICENSE).
