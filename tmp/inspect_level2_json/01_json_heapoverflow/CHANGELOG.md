# Changelog — microjson

## [0.4.2] - 2025-03-18
### Changed
- Refactored the surrogate-pair decoder.
- Added `json_get_number()` lookup helper.

### Known Issues
- **Heap buffer overflow** in `json_parse_string()` when input contains
  many surrogate pairs near the buffer boundary. Tracking as internal
  ticket `MJSON-42`. Patterned after upstream
  [CVE-2019-11834](https://nvd.nist.gov/vuln/detail/CVE-2019-11834).
  See [docs/vulnerability.md](docs/vulnerability.md).

## [0.4.1] - 2025-02-04
### Fixed
- Recursion depth limit for nested arrays/objects (`JSON_MAX_DEPTH`).

## [0.4.0] - 2025-01-09
### Added
- Initial public release of the microjson fork.
- Parser surface: object, array, string, number, bool, null.
