# Security Policy — microjson

## Status

microjson is **intentionally vulnerable** in the 0.4.x series. Do NOT
deploy this code. It exists as an audit-pipeline benchmark.

## Known Vulnerabilities

| ID         | CWE     | Location                              | Notes                                           |
|------------|---------|---------------------------------------|-------------------------------------------------|
| MJSON-42   | CWE-122 | `src/json_parser.c::json_parse_string` | Surrogate-pair overflow, see `docs/vulnerability.md` |

The MJSON-42 pattern is modeled after upstream cJSON CVE-2019-11834.

## Reporting

For unintended vulnerabilities (i.e. bugs other than MJSON-42), please
open a ticket describing the offending input and the observed sanitizer
output.

## Supported Versions

| Version | Supported            |
|---------|----------------------|
| 0.4.x   | :white_check_mark:   |
| < 0.4   | :x:                  |
