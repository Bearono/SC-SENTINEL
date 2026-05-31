import re
from collections import defaultdict

INCLUDE_PATTERN = re.compile(r'^\s*#\s*include\s*[<"]([^>"]+)[>"]', re.MULTILINE)

KNOWN_LIBS = {
    "openssl": {
        "headers": ["openssl/ssl.h", "openssl/crypto.h", "openssl/evp.h"],
        "metadata_keywords": ["OpenSSL", "ssl", "crypto"]
    },
    "libpng": {
        "headers": ["png.h"],
        "metadata_keywords": ["PNG", "png"]
    },
    "zlib": {
        "headers": ["zlib.h"],
        "metadata_keywords": ["ZLIB", "zlib"]
    },
    "curl": {
        "headers": ["curl/curl.h"],
        "metadata_keywords": ["CURL", "curl"]
    },
    "sqlite": {
        "headers": ["sqlite3.h"],
        "metadata_keywords": ["SQLite3", "sqlite3"]
    }
}

def extract_includes(source_files):
    includes = []
    for f in source_files:
        for header in INCLUDE_PATTERN.findall(f["content"]):
            includes.append({"file": f["relative_path"], "header": header})
    return includes

def infer_components(source_files, metadata_files):
    evidence = defaultdict(list)

    for item in extract_includes(source_files):
        for lib_name, info in KNOWN_LIBS.items():
            if item["header"] in info["headers"]:
                evidence[lib_name].append({
                    "source": "include",
                    "file": item["file"],
                    "evidence": f'#include <{item["header"]}>'
                })

    for mf in metadata_files:
        for lib_name, info in KNOWN_LIBS.items():
            for keyword in info["metadata_keywords"]:
                if keyword in mf["content"]:
                    evidence[lib_name].append({
                        "source": mf["name"],
                        "file": mf["relative_path"],
                        "evidence": keyword
                    })

    return [
        {"name": name, "version": "unknown", "evidence": ev}
        for name, ev in evidence.items()
    ]
