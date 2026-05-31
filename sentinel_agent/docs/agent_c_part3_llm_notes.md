# Agent C Part 3: LLM Static Audit

## Goal

Upgrade Agent C from rule-only audit to LLM semantic audit.

## Files added / modified

- `core/env_loader.py`
- `core/llm_client.py`
- `prompts/static_audit_prompt.txt`
- `agents/agent_c_static_audit.py`
- `.env.example`

## Environment variables

Create `.env` in project root:

```text
LLM_API_KEY=your_api_key_here
LLM_BASE_URL=https://your-provider.example/v1
LLM_MODEL=your-model-name
LLM_TIMEOUT=60
LLM_TEMPERATURE=0
```

## Behavior

If `.env` is not configured:

```text
audit_mode = rule_fallback_only
```

If `.env` is configured and LLM call succeeds:

```text
audit_mode = llm_with_rule_fallback
```

If LLM fails, Agent C automatically uses rule fallback and records the error in:

```text
llm_errors
```

## Output fields

`outputs/agent_c_findings.json` now includes:

```json
{
  "audit_mode": "llm_with_rule_fallback",
  "llm_errors": [],
  "summary": {
    "llm_available": true,
    "llm_error_count": 0
  }
}
```
