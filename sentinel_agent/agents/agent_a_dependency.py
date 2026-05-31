from core.risk_level import max_risk
from cve.dependency_parser import infer_components, deduplicate_evidence
from cve.nvd_client import query_nvd_by_keyword
from cve.osv_client import query_osv_package
from cve.risk_inference import normalize_vulnerability_risk


def run_agent_a(source_files, metadata_files):
    """
    Agent A - Dependency Risk Identification

    Part 2.1 upgraded version:
    - Keeps Part 2 dependency parsing and OSV/NVD query.
    - Infers risk from vulnerability text when CVSS/severity is missing.
    - Splits full vulnerability list and top risk list.
    - Avoids "component has memory corruption records but risk remains unknown".
    """
    components = infer_components(source_files, metadata_files)

    enriched = []
    for component in components:
        name = component["name"]
        version = component.get("version", "unknown")
        purl_name = component.get("purl_name", name)
        ecosystem_candidates = component.get("ecosystem_candidates", [])

        osv_vulns = query_osv_package(
            purl_name,
            version=version,
            ecosystem_candidates=ecosystem_candidates
        )
        nvd_vulns = query_nvd_by_keyword(name)

        matched = deduplicate_vulnerabilities(osv_vulns + nvd_vulns)
        matched = [normalize_vulnerability_risk(v) for v in matched]
        matched = sort_vulnerabilities_by_risk(matched)

        risk = "unknown"
        for item in matched:
            risk = max_risk(risk, item.get("risk_level", "unknown"))

        evidence = deduplicate_evidence(component.get("evidence", []))
        source_types = sorted({item.get("source") for item in evidence if item.get("source")})

        enriched.append({
            "name": name,
            "version": version,
            "purl_name": purl_name,
            "source_types": source_types,
            "evidence": evidence,

            # Full list for backend / report export.
            "matched_vulnerabilities": matched,

            # Compatibility with existing Agent E/report code.
            "matched_cves": matched,

            # Short list for frontend table preview.
            "top_vulnerabilities": matched[:5],

            "risk_level": risk,
            "summary": {
                "vulnerability_count": len(matched),
                "highest_risk": risk,
                "high_or_critical_count": sum(
                    1 for v in matched if v.get("risk_level") in {"high", "critical"}
                ),
                "queried_sources": ["OSV", "NVD"]
            }
        })

    return {
        "agent": "Agent A - Dependency Risk Identification",
        "components": enriched,
        "summary": {
            "total_components": len(enriched),
            "high_risk_components": sum(
                1 for c in enriched if c.get("risk_level") in {"high", "critical"}
            ),
            "queried_sources": ["OSV", "NVD"]
        }
    }


def deduplicate_vulnerabilities(vulns):
    seen = set()
    result = []
    for vuln in vulns:
        key = vuln.get("cve_id") or vuln.get("id") or vuln.get("summary")
        if key in seen:
            continue
        seen.add(key)
        result.append(vuln)
    return result


def sort_vulnerabilities_by_risk(vulns):
    order = {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1,
        "unknown": 0
    }
    return sorted(
        vulns,
        key=lambda v: (
            order.get(v.get("risk_level", "unknown"), 0),
            v.get("published") or ""
        ),
        reverse=True
    )
