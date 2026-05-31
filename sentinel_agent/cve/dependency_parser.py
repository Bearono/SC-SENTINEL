import json
import re
from collections import defaultdict

INCLUDE_PATTERN = re.compile(r'^\s*#\s*include\s*[<"]([^>"]+)[>"]', re.MULTILINE)

# Alias dictionary: map headers / CMake names / package names to normalized component names.
KNOWN_COMPONENTS = {
    "openssl": {
        "headers": ["openssl/ssl.h", "openssl/crypto.h", "openssl/evp.h", "openssl/bio.h"],
        "keywords": ["openssl", "ssl", "crypto", "openssl::ssl", "openssl::crypto"],
        "ecosystem_candidates": ["OSS-Fuzz"],
        "purl_name": "openssl"
    },
    "libpng": {
        "headers": ["png.h"],
        "keywords": ["libpng", "png", "png::png"],
        "ecosystem_candidates": ["OSS-Fuzz"],
        "purl_name": "libpng"
    },
    "zlib": {
        "headers": ["zlib.h"],
        "keywords": ["zlib", "zlib::zlib"],
        "ecosystem_candidates": ["OSS-Fuzz"],
        "purl_name": "zlib"
    },
    "curl": {
        "headers": ["curl/curl.h"],
        "keywords": ["curl", "libcurl", "curl::libcurl"],
        "ecosystem_candidates": ["OSS-Fuzz"],
        "purl_name": "curl"
    },
    "sqlite": {
        "headers": ["sqlite3.h"],
        "keywords": ["sqlite", "sqlite3", "sqlite::sqlite3"],
        "ecosystem_candidates": ["OSS-Fuzz"],
        "purl_name": "sqlite"
    },
    "libxml2": {
        "headers": ["libxml/parser.h", "libxml/tree.h"],
        "keywords": ["libxml2", "xml2"],
        "ecosystem_candidates": ["OSS-Fuzz"],
        "purl_name": "libxml2"
    }
}


def extract_includes(source_files):
    includes = []
    for f in source_files:
        for header in INCLUDE_PATTERN.findall(f["content"]):
            includes.append({
                "file": f["relative_path"],
                "header": header
            })
    return includes


def infer_components(source_files, metadata_files):
    evidence = defaultdict(list)

    _infer_from_includes(source_files, evidence)
    _infer_from_metadata(metadata_files, evidence)

    components = []
    for name, ev in evidence.items():
        info = KNOWN_COMPONENTS.get(name, {})
        components.append({
            "name": name,
            "version": infer_version_from_evidence(ev),
            "evidence": ev,
            "ecosystem_candidates": info.get("ecosystem_candidates", []),
            "purl_name": info.get("purl_name", name)
        })

    return components


def _infer_from_includes(source_files, evidence):
    for item in extract_includes(source_files):
        header = item["header"].lower()
        for component_name, info in KNOWN_COMPONENTS.items():
            if header in [h.lower() for h in info.get("headers", [])]:
                evidence[component_name].append({
                    "source": "include",
                    "file": item["file"],
                    "evidence": f'#include <{item["header"]}>',
                    "version_hint": None
                })


def _infer_from_metadata(metadata_files, evidence):
    for mf in metadata_files:
        name = mf["name"].lower()
        content = mf["content"]

        if name == "cmakelists.txt":
            _parse_cmake(mf, evidence)
        elif name in {"makefile", "makefile"}:
            _parse_makefile(mf, evidence)
        elif name == "vcpkg.json":
            _parse_vcpkg_json(mf, evidence)
        elif name == "conanfile.txt":
            _parse_conanfile(mf, evidence)
        else:
            _parse_generic_metadata(mf, evidence)


def _parse_cmake(mf, evidence):
    text = mf["content"]
    lower = text.lower()

    # find_package(OpenSSL REQUIRED)
    for pkg in re.findall(r'find_package\s*\(\s*([A-Za-z0-9_\-]+)', text, flags=re.IGNORECASE):
        normalized = normalize_component_name(pkg)
        if normalized:
            evidence[normalized].append({
                "source": "CMakeLists.txt",
                "file": mf["relative_path"],
                "evidence": f"find_package({pkg})",
                "version_hint": None
            })

    # target_link_libraries(app OpenSSL::SSL zlib ...)
    for component_name, info in KNOWN_COMPONENTS.items():
        for keyword in info.get("keywords", []):
            if keyword.lower() in lower:
                evidence[component_name].append({
                    "source": "CMakeLists.txt",
                    "file": mf["relative_path"],
                    "evidence": keyword,
                    "version_hint": None
                })


def _parse_makefile(mf, evidence):
    lower = mf["content"].lower()
    for component_name, info in KNOWN_COMPONENTS.items():
        for keyword in info.get("keywords", []):
            if keyword.lower() in lower:
                evidence[component_name].append({
                    "source": mf["name"],
                    "file": mf["relative_path"],
                    "evidence": keyword,
                    "version_hint": None
                })


def _parse_vcpkg_json(mf, evidence):
    try:
        data = json.loads(mf["content"])
    except Exception:
        return

    dependencies = data.get("dependencies", [])
    for dep in dependencies:
        if isinstance(dep, str):
            dep_name = dep
            version_hint = None
        elif isinstance(dep, dict):
            dep_name = dep.get("name")
            version_hint = dep.get("version>=") or dep.get("version") or dep.get("version-string")
        else:
            continue

        normalized = normalize_component_name(dep_name)
        if normalized:
            evidence[normalized].append({
                "source": "vcpkg.json",
                "file": mf["relative_path"],
                "evidence": dep_name,
                "version_hint": version_hint
            })


def _parse_conanfile(mf, evidence):
    for line in mf["lines"]:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        # Common form: openssl/1.1.1t
        match = re.match(r'([A-Za-z0-9_\-]+)\s*/\s*([A-Za-z0-9_\.\-\+]+)', stripped)
        if not match:
            continue

        dep_name, version = match.group(1), match.group(2)
        normalized = normalize_component_name(dep_name)
        if normalized:
            evidence[normalized].append({
                "source": "conanfile.txt",
                "file": mf["relative_path"],
                "evidence": stripped,
                "version_hint": version
            })


def _parse_generic_metadata(mf, evidence):
    lower = mf["content"].lower()
    for component_name, info in KNOWN_COMPONENTS.items():
        for keyword in info.get("keywords", []):
            if keyword.lower() in lower:
                evidence[component_name].append({
                    "source": mf["name"],
                    "file": mf["relative_path"],
                    "evidence": keyword,
                    "version_hint": None
                })


def normalize_component_name(name):
    if not name:
        return None
    lower = str(name).strip().lower()

    # Direct alias match.
    alias_map = {
        "openssl": "openssl",
        "ssl": "openssl",
        "crypto": "openssl",
        "libssl": "openssl",
        "libcrypto": "openssl",

        "png": "libpng",
        "libpng": "libpng",

        "zlib": "zlib",

        "curl": "curl",
        "libcurl": "curl",

        "sqlite": "sqlite",
        "sqlite3": "sqlite",

        "xml2": "libxml2",
        "libxml2": "libxml2",
    }

    if lower in alias_map:
        return alias_map[lower]

    for component_name, info in KNOWN_COMPONENTS.items():
        if lower in [kw.lower() for kw in info.get("keywords", [])]:
            return component_name

    return None


def infer_version_from_evidence(evidence_items):
    for item in evidence_items:
        if item.get("version_hint"):
            return item["version_hint"]
    return "unknown"


def deduplicate_evidence(evidence_items):
    seen = set()
    result = []
    for item in evidence_items:
        key = (item.get("source"), item.get("file"), item.get("evidence"), item.get("version_hint"))
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return result
