# Sentinel-Bench Level 2: Multi-File CVE Replica Suite

[![License](https://img.shields.io/badge/license-mixed-blue.svg)](#projects)
[![Version](https://img.shields.io/badge/version-2025.04-green.svg)](#release-notes)

Six self-contained, vulnerable-by-design C projects shaped like real
OSS libraries. Each project is structured to feed the full SENTINEL
audit pipeline (Agent A → E) end-to-end:

- **Agent A** picks up the third-party dependency manifest
  (`vcpkg.json` / `conanfile.txt`) and CVE-bearing version pins.
- **Agent B** slices the per-function vulnerable call paths.
- **Agent C** correlates the slice against the CWE class shipped in
  `docs/vulnerability.md`.
- **Agent D** generates an AFL++/libFuzzer harness against the entry
  surface declared in the project's `Makefile` / `CMakeLists.txt`.
- **Agent E** correlates ASan / AFL++ / eBPF runtime evidence against
  the static finding to produce a confirmed verdict.

## Projects

| # | Slug                       | Library Persona | CWE     | Inspired by CVE                       |
|---|----------------------------|-----------------|---------|---------------------------------------|
| 1 | `01_json_heapoverflow`     | microjson 0.4.2 | CWE-122 | CVE-2019-11834 (cJSON)                |
| 2 | `02_png_uaf`               | pngreader 1.6.36| CWE-416 | CVE-2019-7317 (libpng)                |
| 3 | `03_modbus_stackoverflow`  | modlite 3.1.6   | CWE-121 | CVE-2022-0367 / CVE-2024-10918 (libmodbus) |
| 4 | `04_tree_doublefree`       | astlite 0.2.0   | CWE-415 | cJSON issue #833                      |
| 5 | `05_chunked_intoverflow`   | httpdecode 2.0.20| CWE-190 → CWE-122 | CVE-2017-8798 (miniupnpc / curl)      |
| 6 | `06_adpcm_oobread`         | sndmini 1.0.28  | CWE-125 | CVE-2021-3246 (libsndfile)            |

## Project Layout (canonical)

```
<slug>/
├── README.md             project description & build instructions
├── LICENSE               upstream-derived license
├── VERSION               semver tag matching the vulnerable release
├── CHANGELOG.md          history, including the deliberately retained bug
├── SECURITY.md           disclosure policy & known issues
├── conanfile.txt | vcpkg.json   dependency manifest (when applicable)
├── CMakeLists.txt        CMake build (asan / afl / install / tests)
├── Makefile              POSIX build (normal / asan / afl / test / clean)
├── .gitignore
├── include/<name>.h      public API
├── src/<name>.c          implementation (VULNERABLE)
├── src/main.c            CLI driver
├── seeds/                AFL++ initial corpus + PoC trigger
└── docs/vulnerability.md detailed bug description & detection guide
```

## Building Everything

```bash
for p in 01_* 02_* 03_* 04_* 05_* 06_*; do
    echo "=== $p ===";
    (cd $p && make asan && ./*_asan seeds/*) || true;
done
```

## Submitting to SENTINEL

Each project directory is a complete, independent input to the
SENTINEL pipeline. Zip an individual project (e.g.
`zip -r microjson.zip 01_json_heapoverflow`) and upload it via the
SENTINEL frontend, or pass the directory path to the agent CLI:

```bash
python sentinel_agent/main.py \
    --project sentinel_agent/samples/level2_testset/01_json_heapoverflow \
    --output  outputs_level2/01_json
```

## Disclaimer

Every project in this suite is **intentionally vulnerable**. Do not
deploy, do not link into production, and do not expose the binaries to
any network. See each project's `SECURITY.md`.
