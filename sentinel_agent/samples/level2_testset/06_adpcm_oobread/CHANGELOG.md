# Changelog — sndmini

## [1.0.28] - 2025-04-02
### Changed
- Added `samples_per_block` validation to `adpcm_parse_wav()`.

### Known Issues
- **Out-of-bounds read** in `adpcm_decode_block()` when the FMT
  chunk's `samples_per_block` is smaller than what the DATA chunk
  encodes. Tracking as `SM-031`. Patterned after CVE-2021-3246.

## [1.0.20] - 2024-12-12
### Fixed
- 24-bit PCM endian handling.

## [1.0.0] - 2024-07-04
### Added
- Initial release of sndmini.
