# Agent C Part 3.2: LLM Output Quality Control

## Added features

1. JSON parse retry / repair
2. Confidence calibration
3. LLM vs rule consistency check
4. `quality_control` metadata per finding
5. `quality_summary` in Agent C output

## Confidence calibration policy

- consistent with rule baseline: cap at 0.95
- LLM-only with evidence: cap at 0.85
- line overlap but CWE conflict: cap at 0.70
- missing evidence or trigger condition: cap at 0.70

## New fields

Each finding may include:

```json
"quality_control": {
  "original_confidence": 1.0,
  "calibrated_confidence": 0.95,
  "confidence_adjusted": true,
  "rule_consistency": "consistent",
  "matched_rule_cwe": "CWE-416",
  "matched_rule_line_range": [10, 13],
  "warnings": ["confidence_adjusted_from_1.0_to_0.95"]
}
```

Agent output includes:

```json
"quality_summary": {
  "confidence_adjusted_count": 4,
  "consistent_with_rule_count": 4,
  "cwe_conflict_count": 0
}
```
