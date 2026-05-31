# SENTINEL Risk Level Standard

## Dependency risk

- critical: CVSS >= 9.0
- high: 7.0 <= CVSS < 9.0
- medium: 4.0 <= CVSS < 7.0
- low: 0.1 <= CVSS < 4.0
- unknown: no CVSS or no matched CVE

## Static finding risk

- high: UAF, Double Free, confirmed heap/stack overflow pattern
- medium: suspicious dangerous copy but incomplete evidence
- low: weak pattern requiring manual confirmation
