# sndmini

[![License](https://img.shields.io/badge/license-LGPL--2.1-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.0.28-red.svg)](VERSION)
[![CWE](https://img.shields.io/badge/CWE--125-OOB%20Read-critical.svg)](docs/vulnerability.md)
[![Inspired by](https://img.shields.io/badge/inspired_by-CVE--2021--3246-orange.svg)](https://nvd.nist.gov/vuln/detail/CVE-2021-3246)

`sndmini` is a small WAV+MS-ADPCM block decoder, derived from a
stripped fork of `libsndfile`. Version 1.0.28 contains a deliberate
out-of-bounds read regression patterned after
[CVE-2021-3246](https://nvd.nist.gov/vuln/detail/CVE-2021-3246) /
[CVE-2018-13139](https://nvd.nist.gov/vuln/detail/CVE-2018-13139) for
SENTINEL benchmarking.

> :warning: Intentionally-vulnerable code — do not deploy.

## Building

```bash
make
make asan
make afl
make test
```

## Usage

```bash
./adpcm_decoder seeds/seed_01.wav
```

## Dependencies

| Component | Version  | Required | Notes                                   |
|-----------|----------|----------|-----------------------------------------|
| zlib      | 1.2.11   | yes      | used for optional FLAC-ish compression  |

## License

LGPL-2.1 — see [LICENSE](LICENSE).
