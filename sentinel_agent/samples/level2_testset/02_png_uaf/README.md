# pngreader

[![License](https://img.shields.io/badge/license-zlib-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.6.36-red.svg)](VERSION)
[![CWE](https://img.shields.io/badge/CWE--416-Use--After--Free-critical.svg)](docs/vulnerability.md)
[![Inspired by](https://img.shields.io/badge/inspired_by-CVE--2019--7317-orange.svg)](https://nvd.nist.gov/vuln/detail/CVE-2019-7317)

`pngreader` is a minimal PNG-like chunk loader and metadata extractor.
It is a **stripped-down internal fork** of `libpng` that we maintain for
the SENTINEL audit pipeline benchmark. The 1.6.36 line carries a
deliberately retained use-after-free regression modeled after
[CVE-2019-7317](https://nvd.nist.gov/vuln/detail/CVE-2019-7317).

> :warning: Intentionally-vulnerable code — do not deploy.
> See [SECURITY.md](SECURITY.md).

---

## Building

```bash
make            # release
make asan       # AddressSanitizer
make afl        # AFL++ instrumentation
make test       # smoke test against seeds/
```

CMake:

```bash
cmake -B build -DENABLE_ASAN=ON
cmake --build build -j
```

## Usage

```bash
./png_loader seeds/seed_01.png
```

## Fuzzing

```bash
make afl
afl-fuzz -i seeds -o findings -- ./png_loader_afl @@
```

## Dependencies

| Component | Version  | Required | Notes                                |
|-----------|----------|----------|--------------------------------------|
| libpng    | 1.6.36   | yes      | upstream we forked from              |
| zlib      | 1.2.11   | yes      | DEFLATE decompression of IDAT chunks |

See [vcpkg.json](vcpkg.json) for the dependency manifest.

## License

zlib/libpng license — see [LICENSE](LICENSE).
