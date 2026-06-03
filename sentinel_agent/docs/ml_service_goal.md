# SENTINEL ML Seven-Agent Service Goal

## Implemented target

This module implements the ML-owned seven-agent service described in the upgraded project plan:

1. Agent A detects C/C++ third-party components from source includes and build metadata, then queries OSV/NVD.
2. Agent B builds function-level semantic slices with context, call relationships, risk keywords, audit priority, and dataflow hints.
3. Agent C generates vulnerability hypotheses from prioritized slices without making final audit decisions.
4. Agent D performs LLM audit and cross-check against Agent C hypotheses, with rule fallback and quality control metadata.
5. Agent E generates ASan/AFL++/libFuzzer harness packages and records build readiness quality gates.
6. Agent F attributes ASan/AFL++/eBPF runtime evidence to static findings.
7. Agent G makes the final risk decision and writes JSON/Markdown reports.

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

`/api/agent-a/analyze` returns a flat `components` list for `component_risk` rows, plus the rich `agent_a` result and `components_rich` for ML-side reports.

`/api/agent-b/audit` returns a flat `vulnerabilities` list for backend persistence, plus full `agent_a` through `agent_g` outputs and artifact paths.

## Current verified sample result

```text
Components: 6
Hypotheses: 5
Static Findings: 5
Harness Packages: 5
Confirmed Findings: 4
ASan Confirmed Findings: 4
Overall Risk: high
```

