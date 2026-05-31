MOCK_NVD = {
    "openssl": [
        {
            "cve_id": "CVE-2014-0160",
            "cvss": 7.5,
            "risk_level": "high",
            "summary": "Mock: OpenSSL Heartbleed historical vulnerability."
        }
    ],
    "libpng": [
        {
            "cve_id": "CVE-2015-8126",
            "cvss": 7.5,
            "risk_level": "high",
            "summary": "Mock: libpng memory corruption vulnerability."
        }
    ],
    "zlib": [],
    "curl": [],
    "sqlite": []
}

def query_nvd_by_keyword(component_name):
    return MOCK_NVD.get(component_name.lower(), [])
