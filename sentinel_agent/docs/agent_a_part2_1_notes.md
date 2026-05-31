# Agent A Part 2.1 Notes

## Problem

OSV OSS-Fuzz records often do not contain CVSS scores.
Part 2 could successfully retrieve vulnerabilities, but many risk levels stayed `unknown`.

## Fix

Part 2.1 adds text-based risk inference:

- heap-use-after-free -> high
- use-after-free -> high
- heap-buffer-overflow -> high
- stack-buffer-overflow -> high
- double-free -> high
- null-dereference -> medium
- memory leak -> low

## New output fields

Each component now includes:

```json
{
  "top_vulnerabilities": [],
  "summary": {
    "vulnerability_count": 10,
    "highest_risk": "high",
    "high_or_critical_count": 7
  }
}
```
