# Agent A Part 2 Notes

## Goal

Agent A identifies third-party C/C++ components and checks known vulnerability databases.

## Supported evidence sources

- `#include`
- `CMakeLists.txt`
- `Makefile`
- `vcpkg.json`
- `conanfile.txt`

## Supported normalized components

- openssl
- libpng
- zlib
- curl
- sqlite
- libxml2

## Vulnerability databases

- OSV.dev API
- NVD CVE API 2.0

## Cache

All API results are cached in:

```text
cve/cve_cache.json
```

If API requests fail, the pipeline continues and returns an empty vulnerability list for that source.
