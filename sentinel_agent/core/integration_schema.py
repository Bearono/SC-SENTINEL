"""
Backend integration schema adapters for SENTINEL agent outputs.

The agent pipeline keeps rich research-oriented structures internally. These
helpers expose the flatter JSON shapes required by sentinel_backend's
INTEGRATION_GUIDE.md without breaking the existing report flow.
"""


SEVERITY_VALUES = {"critical", "high", "medium", "low", "unknown"}

CWE_TO_BACKEND_VULN_TYPE = {
    "CWE-416": "UAF",
    "CWE-415": "double_free",
    "CWE-122": "heap_overflow",
    "CWE-121": "stack_overflow",
    "CWE-134": "format_string",
}

VULN_TYPE_DISPLAY = {
    "UAF": "Use After Free",
    "double_free": "Double Free",
    "heap_overflow": "Heap Buffer Overflow",
    "stack_overflow": "Stack Buffer Overflow",
    "format_string": "Format String",
}


def severity_from_risk(risk):
    risk = str(risk or "unknown").lower()
    return risk if risk in SEVERITY_VALUES else "unknown"


def cvss_from_vulnerability(vuln):
    score = vuln.get("severity_score")
    if score is None:
        score = vuln.get("cvss_score")
    try:
        return float(score) if score is not None else None
    except Exception:
        return None


def nvd_url_from_vulnerability(vuln):
    cve_id = vuln.get("cve_id") or vuln.get("id")
    if cve_id and str(cve_id).startswith("CVE-"):
        return f"https://nvd.nist.gov/vuln/detail/{cve_id}"

    refs = vuln.get("references") or []
    return refs[0] if refs else None


def to_backend_components(agent_a_result):
    """
    Convert Agent A's rich component records into backend ComponentRisk rows.

    If a component has no matched CVE/OSV item, we still emit one row with
    unknown severity so the backend can show that the component was detected.
    """
    rows = []
    for comp in agent_a_result.get("components", []):
        vulns = comp.get("matched_vulnerabilities") or comp.get("matched_cves") or []

        if not vulns:
            rows.append({
                "library_name": comp.get("library_name") or comp.get("name"),
                "version": comp.get("version", "unknown"),
                "cve_id": None,
                "cvss_score": None,
                "severity": severity_from_risk(comp.get("risk_level")),
                "description": "Component detected; no matched vulnerability was returned by OSV/NVD.",
                "nvd_url": None,
            })
            continue

        for vuln in vulns:
            rows.append({
                "library_name": comp.get("library_name") or comp.get("name"),
                "version": comp.get("version", "unknown"),
                "cve_id": vuln.get("cve_id") or vuln.get("id"),
                "cvss_score": cvss_from_vulnerability(vuln),
                "severity": severity_from_risk(vuln.get("risk_level")),
                "description": vuln.get("summary") or vuln.get("details") or "",
                "nvd_url": nvd_url_from_vulnerability(vuln),
            })

    return {"components": rows}


def to_backend_vuln_type(finding):
    return CWE_TO_BACKEND_VULN_TYPE.get(
        finding.get("cwe_id"),
        str(finding.get("vulnerability_type") or "unknown").lower().replace(" ", "_"),
    )


def code_context_from_finding(finding):
    evidence = finding.get("evidence") or []
    if evidence:
        return "\n".join(str(item) for item in evidence[:6])
    return finding.get("code_context") or ""


def to_backend_vulnerabilities(agent_c_result):
    rows = []
    for finding in agent_c_result.get("static_findings", []):
        line_range = finding.get("line_range") or [None, None]
        line_number = line_range[0] if isinstance(line_range, list) and line_range else None
        rows.append({
            "vuln_type": to_backend_vuln_type(finding),
            "vuln_type_display": VULN_TYPE_DISPLAY.get(to_backend_vuln_type(finding), finding.get("vulnerability_type", "Unknown")),
            "file_path": finding.get("file"),
            "line_number": line_number,
            "code_context": code_context_from_finding(finding),
            "trigger_cond": finding.get("trigger_condition", ""),
            "fix_advice": finding.get("suggested_fix", ""),
            "confidence": finding.get("confidence"),
            "source_slice_id": finding.get("source_slice_id"),
            "hypothesis_id": finding.get("hypothesis_id"),
            "finding_id": finding.get("finding_id"),
            "trace_summary": " -> ".join(finding.get("cross_function_trace") or finding.get("dataflow_trace") or []),
            "dynamic_status": finding.get("dynamic_status", "untriggered"),
            "final_status": finding.get("final_status", "need_review"),
        })
    return {"vulnerabilities": rows}
