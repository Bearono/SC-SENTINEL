# SENTINEL ML Service Goal

## Implemented target

This module implements the ML-owned five-agent service described in the project plan:

1. Agent A detects C/C++ third-party components from source includes and build metadata, then queries OSV/NVD.
2. Agent B builds function-level code slices with context, call relationships, risk keywords, and audit priority.
3. Agent C performs LLM static audit with rule fallback and quality control metadata.
4. Agent D generates ASan/AFL++/libFuzzer harness packages for static findings.
5. Agent E merges static findings, harness metadata, and optional dynamic evidence into final reports.

The service exposes the backend-facing endpoints already configured in `sentinel_backend`:

- `POST /api/agent-a/analyze`
- `POST /api/agent-b/audit`
- `GET /health`

## Run

```bash
cd sentinel_agent
python -m uvicorn service:app --host 127.0.0.1 --port 18001
```

For backend integration, set `ML_MOCK_MODE=false` in the backend environment.

## Backend contract

`/api/agent-a/analyze` returns a flat `components` list for `component_risk` rows, plus the rich `agent_a` result for ML-side reports.

`/api/agent-b/audit` runs Agent A through Agent E and returns a flat `vulnerabilities` list for backend persistence, plus full agent outputs and artifact paths.

