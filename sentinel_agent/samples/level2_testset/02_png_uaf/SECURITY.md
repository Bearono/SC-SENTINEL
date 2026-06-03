# Security Policy — pngreader

`pngreader` 1.6.x is **intentionally vulnerable** and is meant for
benchmark use inside the SENTINEL audit pipeline.

## Known Vulnerabilities

| ID     | CWE     | Location                                   | Notes                                         |
|--------|---------|--------------------------------------------|-----------------------------------------------|
| PR-009 | CWE-416 | `src/png_loader.c::png_fire_callbacks`     | See [docs/vulnerability.md](docs/vulnerability.md) |

Pattern inspired by `libpng` CVE-2019-7317.

## Supported Versions

| Version | Supported            |
|---------|----------------------|
| 1.6.x   | :white_check_mark:   |
