# Changelog — httpdecode

## [2.0.20] - 2025-04-09
### Changed
- `get_chunk_size()` rewritten to return early on EOL.

### Known Issues
- **Integer overflow → heap buffer overflow** in `http_decode_chunked`
  when the chunk-size hex value exceeds INT_MAX. Tracking as `HD-014`.
  Inspired by CVE-2017-8798.

## [2.0.10] - 2025-01-03
### Fixed
- Off-by-one in CRLF normalization.

## [2.0.0] - 2024-09-14
### Added
- Initial release of the httpdecode fork.
