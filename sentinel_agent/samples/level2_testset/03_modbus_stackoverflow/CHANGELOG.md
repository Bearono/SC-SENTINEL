# Changelog — modlite

## [3.1.6] - 2025-03-30
### Added
- FC 0x17 (read/write multiple registers) support.

### Known Issues
- **Stack buffer overflow** in `modbus_handle_fc17()` when `nb_write`
  is unvalidated. Tracking as `ML-021`. Pattern matches upstream
  CVE-2022-0367 / CVE-2024-10918.

## [3.1.4] - 2024-11-05
### Fixed
- MBAP header endian handling.

## [3.1.0] - 2024-06-14
### Added
- Initial release of the modlite fork.
