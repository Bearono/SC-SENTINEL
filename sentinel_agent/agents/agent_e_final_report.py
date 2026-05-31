from pathlib import Path
from core.risk_level import max_risk
from core.json_utils import save_json


def run_agent_e(project_name, agent_a_result, agent_c_result, agent_d_result,
                afl_result, ebpf_log, asan_result=None, output_dir="outputs"):
    asan_result = asan_result or {}

    final_findings = []
    for finding in agent_c_result.get("static_findings", []):
        asan_evidence = match_asan_evidence(finding, asan_result)
        afl_evidence = match_afl_evidence(afl_result)
        ebpf_evidence = match_ebpf_events(finding, ebpf_log)

        dynamic_status, evidence_level, evidence_sources = judge_dynamic_status(
            finding=finding,
            asan_evidence=asan_evidence,
            afl_evidence=afl_evidence,
            ebpf_evidence=ebpf_evidence
        )

        final_findings.append({
            **finding,
            "dynamic_status": dynamic_status,
            "evidence_level": evidence_level,
            "dynamic_evidence_sources": evidence_sources,
            "asan_evidence": asan_evidence,
            "afl_evidence": afl_evidence,
            "ebpf_evidence": ebpf_evidence,
            "final_conclusion": conclusion(dynamic_status, evidence_level, evidence_sources)
        })

    overall_risk = "unknown"
    for comp in agent_a_result.get("components", []):
        overall_risk = max_risk(overall_risk, comp.get("risk_level"))
    for finding in final_findings:
        overall_risk = max_risk(overall_risk, finding.get("risk_level"))

    report = {
        "agent": "Agent E - Final Judgement and Report",
        "project_name": project_name,
        "status": "completed",
        "overall_risk": overall_risk,
        "summary": {
            "total_components": len(agent_a_result.get("components", [])),
            "total_static_findings": len(agent_c_result.get("static_findings", [])),
            "total_harness_packages": len(agent_d_result.get("harness_packages", [])),
            "confirmed_findings": sum(1 for f in final_findings if f["dynamic_status"] == "confirmed"),
            "need_review_findings": sum(1 for f in final_findings if f["dynamic_status"] == "need_review"),
            "asan_confirmed_findings": count_asan_confirmed(final_findings)
        },
        "component_risks": agent_a_result.get("components", []),
        "final_findings": final_findings,
        "dynamic_validation": {
            "asan_result": asan_result,
            "afl_result": afl_result,
            "ebpf_log": ebpf_log
        },
        "recommendations": [
            "Prioritize findings confirmed by ASan/AFL++/eBPF runtime evidence.",
            "Review high-risk dependency CVEs before release.",
            "Use generated harness packages as reproducible dynamic validation artifacts."
        ]
    }

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    save_json(report, output_dir / "final_report.json")
    (output_dir / "final_report.md").write_text(to_markdown(report), encoding="utf-8")
    return report


def judge_dynamic_status(finding, asan_evidence, afl_evidence, ebpf_evidence):
    sources = []
    if asan_evidence and asan_evidence.get("dynamic_status") == "confirmed":
        sources.append("ASAN")
    if afl_evidence and afl_evidence.get("crash_found"):
        sources.append("AFL++")
    if ebpf_evidence:
        sources.append("eBPF")

    if "ASAN" in sources:
        if "eBPF" in sources or "AFL++" in sources:
            return "confirmed", "strong", sources
        return "confirmed", "high", sources
    if "AFL++" in sources and "eBPF" in sources:
        return "confirmed", "strong", sources
    if sources:
        return "need_review", "medium", sources
    return "untriggered", "weak", sources


def match_asan_evidence(finding, asan_result):
    if not asan_result:
        return None
    results_by_id = asan_result.get("results_by_finding_id", {})
    item = results_by_id.get(finding.get("finding_id"))
    if item:
        return item
    for candidate in asan_result.get("results", []):
        if candidate.get("cwe_id") == finding.get("cwe_id") and candidate.get("target_function") == finding.get("function"):
            return candidate
    return None


def match_afl_evidence(afl_result):
    if not afl_result or not afl_result.get("crash_found"):
        return None
    return {
        "crash_found": afl_result.get("crash_found"),
        "crash_file": afl_result.get("crash_file"),
        "signal": afl_result.get("signal"),
        "stderr_excerpt": afl_result.get("stderr_excerpt"),
        "notes": afl_result.get("notes", "AFL++ evidence.")
    }


def match_ebpf_events(finding, ebpf_log):
    if not ebpf_log:
        return []
    cwe = finding.get("cwe_id")
    desired = {
        "CWE-416": {"free", "use_after_free_suspected"},
        "CWE-415": {"free", "double_free_suspected"},
        "CWE-122": {"malloc", "heap_overflow_suspected"},
        "CWE-121": {"stack_write_suspected"}
    }.get(cwe, set())
    return [ev for ev in ebpf_log.get("events", []) if ev.get("event_type") in desired]


def conclusion(dynamic_status, evidence_level, evidence_sources):
    source_text = ", ".join(evidence_sources) if evidence_sources else "no runtime evidence"
    if dynamic_status == "confirmed":
        return f"This suspected vulnerability is dynamically confirmed by {source_text}. Evidence level: {evidence_level}."
    if dynamic_status == "need_review":
        return f"This suspected vulnerability has partial runtime evidence from {source_text} and needs manual review."
    return "This suspected vulnerability was not triggered in the current dynamic validation run."


def count_asan_confirmed(final_findings):
    return sum(1 for f in final_findings if f.get("asan_evidence", {}).get("dynamic_status") == "confirmed")


def to_markdown(report):
    lines = []
    lines.append(f"# SENTINEL Final Audit Report: {report['project_name']}")
    lines.append("")
    lines.append(f"- Overall Risk: **{report['overall_risk']}**")
    lines.append(f"- Total Components: {report['summary']['total_components']}")
    lines.append(f"- Total Static Findings: {report['summary']['total_static_findings']}")
    lines.append(f"- Confirmed Findings: {report['summary']['confirmed_findings']}")
    lines.append(f"- ASan Confirmed Findings: {report['summary'].get('asan_confirmed_findings', 0)}")
    lines.append("")

    lines.append("## Component Risks")
    if not report["component_risks"]:
        lines.append("No dependency risks were inferred.")
    else:
        for comp in report["component_risks"]:
            lines.append(f"### {comp['name']}")
            lines.append(f"- Version: {comp.get('version', 'unknown')}")
            lines.append(f"- Risk: {comp.get('risk_level', 'unknown')}")
            vulns = comp.get("top_vulnerabilities") or comp.get("matched_cves", [])[:5]
            for vuln in vulns:
                vuln_id = vuln.get("cve_id") or vuln.get("id")
                lines.append(f"- {vuln_id}: {vuln.get('summary', '')}")
            lines.append("")

    lines.append("## Final Findings")
    if not report["final_findings"]:
        lines.append("No static findings were generated.")
    else:
        for f in report["final_findings"]:
            lines.append(f"### {f['finding_id']} - {f['vulnerability_type']}")
            lines.append(f"- File: `{f['file']}`")
            lines.append(f"- Function: `{f['function']}`")
            lines.append(f"- Line Range: {f['line_range']}")
            lines.append(f"- CWE: {f['cwe_id']}")
            lines.append(f"- Static Status: {f['static_status']}")
            lines.append(f"- Dynamic Status: **{f['dynamic_status']}**")
            lines.append(f"- Evidence Level: {f['evidence_level']}")
            lines.append(f"- Dynamic Evidence Sources: {', '.join(f.get('dynamic_evidence_sources', [])) or 'none'}")
            asan = f.get("asan_evidence")
            if asan:
                lines.append(f"- ASan Bug Type: `{asan.get('asan_bug_type')}`")
                lines.append(f"- ASan Consistency: `{asan.get('consistency')}`")
                if asan.get("log_file"):
                    lines.append(f"- ASan Log: `{asan.get('log_file')}`")
                for ev in asan.get("evidence", [])[:6]:
                    lines.append(f"  - {ev}")
            lines.append(f"- Trigger Condition: {f.get('trigger_condition', '')}")
            lines.append(f"- Fix Suggestion: {f.get('suggested_fix', '')}")
            lines.append(f"- Final Conclusion: {f['final_conclusion']}")
            lines.append("")
    return "\n".join(lines)
