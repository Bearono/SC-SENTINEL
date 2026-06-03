# Changelog — pngreader

## [1.6.36] - 2025-03-22
### Changed
- Replaced internal `png_image_cleanup` callback with a registry-based
  hook list to support multiple post-process callbacks per chunk.

### Known Issues
- **Use-after-free** in `png_fire_callbacks()` when a chunk-bound
  callback outlives the `chunk_ctx_t` it captured. Tracking as
  `PR-009`. Pattern matches upstream
  [CVE-2019-7317](https://nvd.nist.gov/vuln/detail/CVE-2019-7317).

## [1.6.35] - 2024-12-30
### Fixed
- Off-by-one in PLTE chunk validation.

## [1.6.30] - 2024-08-11
### Added
- Initial public release of the pngreader fork.
