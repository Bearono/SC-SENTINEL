# Part 3.1 LLM Connection Fix

## Why

The log shows:

```text
SSL: UNEXPECTED_EOF_WHILE_READING
```

This usually means the HTTPS connection was interrupted by one of these:

- Wrong `LLM_BASE_URL`
- Provider endpoint does not support the current URL form
- Corporate / campus / local proxy intercepting TLS
- Python urllib SSL compatibility issue on Windows / Conda
- Self-signed internal gateway certificate

## What changed

`core/llm_client.py` now:

- Prefers `requests` when installed
- Falls back to `urllib`
- Supports `LLM_DISABLE_PROXY=1`
- Supports `LLM_VERIFY_SSL=0` for debugging trusted internal gateways
- Adds `tools/test_llm_connection.py`

## Recommended test

```powershell
pip install requests
python tools/test_llm_connection.py
```

## Optional .env flags

```text
LLM_DISABLE_PROXY=1
LLM_VERIFY_SSL=1
```

Only use this for debugging trusted internal gateways:

```text
LLM_VERIFY_SSL=0
```
