# httpdecode

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-2.0.20-red.svg)](VERSION)
[![CWE](https://img.shields.io/badge/CWE--190%2F122-Int%20Overflow-critical.svg)](docs/vulnerability.md)
[![Inspired by](https://img.shields.io/badge/inspired_by-CVE--2017--8798-orange.svg)](https://nvd.nist.gov/vuln/detail/CVE-2017-8798)

`httpdecode` is a minimal HTTP/1.1 response decoder focused on the
chunked transfer encoding. It is a learning-grade fork extracted from
the `curl` codebase, **intentionally retaining** an
integer-signedness regression in the chunk-size parser modeled after
[CVE-2017-8798](https://nvd.nist.gov/vuln/detail/CVE-2017-8798).

> :warning: Do not deploy this code on any network-exposed service.

## Building

```bash
make            # release
make asan       # AddressSanitizer
make afl        # AFL++ instrumented
make test       # regression smoke run
```

## Usage

```bash
./http_decoder seeds/seed_01.http
```

## Dependencies

| Component | Version  | Required | Notes                                   |
|-----------|----------|----------|-----------------------------------------|
| curl      | 7.79.0   | runtime  | upstream we cherry-picked the parser from |

Declared in [conanfile.txt](conanfile.txt).

## License

MIT — see [LICENSE](LICENSE).
