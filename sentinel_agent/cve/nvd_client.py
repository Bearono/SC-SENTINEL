import json
import os
import urllib.parse
import urllib.request

from cve.cve_cache import get_cache, set_cache

NVD_CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def query_nvd_by_keyword(component_name, results_per_page=10, timeout=10):
    """
    Query NVD CVE API 2.0 with keywordSearch.

    This is broader than OSV and useful for C/C++ libraries where package ecosystems
    may not be standardized.

    The function is deliberately conservative:
    - small results_per_page
    - local cache
    - optional NVD_API_KEY from environment
    - pipeline does not fail if NVD is unavailable
    """
    cache_key = f"nvd:keyword:{component_name}:rpp{results_per_page}"
    cached = get_cache(cache_key)
    if cached is not None:
        return cached

    params = {
        "keywordSearch": component_name,
        "resultsPerPage": str(results_per_page),
        "startIndex": "0"
    }

    url = NVD_CVE_API_URL + "?" + urllib.parse.urlencode(params)
    headers = {}
    api_key = os.getenv("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key

    try:
        req = urllib.request.Request(url, headers=headers, method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        vulns = data.get("vulnerabilities", [])
        normalized = [normalize_nvd_item(item) for item in vulns]
        set_cache(cache_key, normalized)
        return normalized
    except Exception:
        set_cache(cache_key, [])
        return []


def normalize_nvd_item(item):
    cve = item.get("cve", {})
    cve_id = cve.get("id")

    descriptions = cve.get("descriptions", [])
    summary = ""
    for desc in descriptions:
        if desc.get("lang") == "en":
            summary = desc.get("value", "")
            break
    if not summary and descriptions:
        summary = descriptions[0].get("value", "")

    cvss = extract_cvss(cve)
    risk_level = score_to_risk(cvss)

    weaknesses = []
    for weakness in cve.get("weaknesses", []):
        for desc in weakness.get("description", []):
            value = desc.get("value")
            if value and value not in weaknesses:
                weaknesses.append(value)

    references = extract_references(cve)

    return {
        "source": "NVD",
        "id": cve_id,
        "cve_id": cve_id,
        "summary": summary[:500],
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "severity_score": cvss,
        "risk_level": risk_level,
        "weaknesses": weaknesses,
        "references": references
    }


def extract_cvss(cve):
    metrics = cve.get("metrics", {})

    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        metric_list = metrics.get(key)
        if not metric_list:
            continue
        metric = metric_list[0]
        cvss_data = metric.get("cvssData", {})
        score = cvss_data.get("baseScore")
        if score is not None:
            try:
                return float(score)
            except Exception:
                return None

    return None


def extract_references(cve):
    refs = cve.get("references", [])

    # NVD API 2.0 returns a list of reference objects:
    # {"references": [{"url": "...", "source": "..."}]}
    if isinstance(refs, list):
        return [ref.get("url") for ref in refs if isinstance(ref, dict) and ref.get("url")][:5]

    # Keep compatibility with the older 1.x style shape.
    if isinstance(refs, dict):
        return [
            ref.get("url")
            for ref in refs.get("referenceData", [])
            if isinstance(ref, dict) and ref.get("url")
        ][:5]

    return []


def score_to_risk(score):
    if score is None:
        return "unknown"
    try:
        score = float(score)
    except Exception:
        return "unknown"

    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "unknown"
