import uuid
from pathlib import Path
import sys
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

AGENT_ROOT = Path(__file__).resolve().parent
if str(AGENT_ROOT) not in sys.path:
    sys.path.insert(0, str(AGENT_ROOT))

from agents.agent_a_dependency import run_agent_a
from agents.agent_b_slicer import run_agent_b
from agents.agent_c_static_audit import run_agent_c
from agents.agent_d_harness import run_agent_d
from agents.agent_e_final_report import run_agent_e
from core.file_scanner import scan_project_metadata_files, scan_source_files
from core.integration_schema import to_backend_components, to_backend_vulnerabilities


class AgentARequest(BaseModel):
    source_root: str | None = None
    dep_files: list[dict[str, Any]] = Field(default_factory=list)
    includes: list[str] = Field(default_factory=list)
    cpp_files: list[str] = Field(default_factory=list)


class AgentBAuditRequest(BaseModel):
    source_root: str
    cpp_files: list[str] = Field(default_factory=list)
    target_vulns: list[str] = Field(default_factory=list)
    generate_harness: bool = True


app = FastAPI(
    title="SENTINEL ML Agent Service",
    version="0.2.0",
    description="Five-agent ML service for dependency CVE analysis, slicing, static audit, harness generation, and final reporting.",
)


@app.get("/health")
def health():
    return {"status": "ok", "service": "sentinel-ml-agent", "version": "0.2.0"}


@app.post("/api/agent-a/analyze")
def analyze_dependencies(request: AgentARequest):
    source_files, metadata_files = load_agent_a_inputs(request)
    result = run_agent_a(source_files, metadata_files)
    backend_components = to_backend_components(result)["components"]
    return {
        "components": backend_components,
        "summary": result.get("summary", {}),
        "agent_a": result,
    }


@app.post("/api/agent-b/audit")
def audit_source(request: AgentBAuditRequest):
    source_root = Path(request.source_root).resolve()
    if not source_root.is_dir():
        raise HTTPException(status_code=400, detail=f"source_root is not a directory: {source_root}")

    run_id = uuid.uuid4().hex[:12]
    output_dir = AGENT_ROOT / "outputs" / f"service_{run_id}"
    harness_dir = AGENT_ROOT / "harness_packages" / f"service_{run_id}"

    source_files = scan_source_files(str(source_root))
    metadata_files = scan_project_metadata_files(str(source_root))

    agent_a_result = run_agent_a(source_files, metadata_files)
    agent_b_result = run_agent_b(source_files)
    agent_c_result = run_agent_c(agent_a_result, agent_b_result)
    filter_findings_by_target_vulns(agent_c_result, request.target_vulns)

    if request.generate_harness:
        agent_d_result = run_agent_d(agent_c_result, harness_root=harness_dir, project_root=source_root)
    else:
        agent_d_result = {
            "agent": "Agent D - Harness Automatic Generation",
            "harness_packages": [],
            "summary": {"total_packages": 0, "packages_by_cwe": {}},
        }

    final_report = run_agent_e(
        project_name=source_root.name,
        agent_a_result=agent_a_result,
        agent_c_result=agent_c_result,
        agent_d_result=agent_d_result,
        afl_result={"crash_found": False},
        ebpf_log={"events": []},
        asan_result={},
        output_dir=output_dir,
    )

    backend_vulns = to_backend_vulnerabilities(agent_c_result)["vulnerabilities"]
    return {
        "vulnerabilities": backend_vulns,
        "summary": {
            "components": agent_a_result.get("summary", {}),
            "slices": agent_b_result.get("summary", {}),
            "findings": agent_c_result.get("summary", {}),
            "harness": agent_d_result.get("summary", {}),
            "overall_risk": final_report.get("overall_risk"),
        },
        "artifacts": {
            "output_dir": str(output_dir),
            "harness_dir": str(harness_dir),
            "final_report_json": str(output_dir / "final_report.json"),
            "final_report_md": str(output_dir / "final_report.md"),
        },
        "agent_a": agent_a_result,
        "agent_b": agent_b_result,
        "agent_c": agent_c_result,
        "agent_d": agent_d_result,
        "final_report": final_report,
    }


def load_agent_a_inputs(request: AgentARequest):
    if request.source_root:
        source_root = Path(request.source_root).resolve()
        if source_root.is_dir():
            return scan_source_files(str(source_root)), scan_project_metadata_files(str(source_root))

    source_files = synthetic_source_files(request.includes, request.cpp_files)
    metadata_files = normalize_dep_files(request.dep_files)
    return source_files, metadata_files


def synthetic_source_files(includes, cpp_files):
    include_lines = [f"#include <{header}>" for header in includes]
    content = "\n".join(include_lines)
    if not content and cpp_files:
        content = "\n".join(f"/* {path} */" for path in cpp_files)
    return [{
        "absolute_path": "<request:includes>",
        "relative_path": cpp_files[0] if cpp_files else "request_includes.c",
        "suffix": ".c",
        "content": content,
        "lines": content.splitlines(),
    }]


def normalize_dep_files(dep_files):
    normalized = []
    for idx, item in enumerate(dep_files or [], start=1):
        name = item.get("name") or item.get("filename") or Path(str(item.get("path", f"dep_{idx}"))).name
        rel = item.get("relative_path") or item.get("path") or name
        content = item.get("content") or ""
        normalized.append({
            "absolute_path": item.get("absolute_path") or f"<request:{rel}>",
            "relative_path": rel,
            "name": name,
            "content": content,
            "lines": content.splitlines(),
        })
    return normalized


def filter_findings_by_target_vulns(agent_c_result, target_vulns):
    if not target_vulns:
        return
    targets = {normalize_target_vuln(item) for item in target_vulns}
    targets.discard("")
    if not targets:
        return

    filtered = []
    for finding in agent_c_result.get("static_findings", []):
        cwe = normalize_target_vuln(finding.get("cwe_id", ""))
        vuln_type = normalize_target_vuln(finding.get("vulnerability_type", ""))
        if cwe in targets or vuln_type in targets:
            filtered.append(finding)

    agent_c_result["static_findings"] = filtered
    agent_c_result["vulnerabilities"] = to_backend_vulnerabilities(agent_c_result)["vulnerabilities"]
    agent_c_result["integration"] = {"vulnerabilities": agent_c_result["vulnerabilities"]}
    agent_c_result["summary"]["total_findings"] = len(filtered)
    agent_c_result["summary"]["high_risk_findings"] = sum(
        1 for f in filtered if f.get("risk_level") in {"high", "critical"}
    )


def normalize_target_vuln(value):
    return str(value or "").strip().lower().replace("_", "-").replace(" ", "-")
