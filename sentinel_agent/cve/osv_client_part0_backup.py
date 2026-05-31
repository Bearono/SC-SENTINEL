MOCK_OSV = {
    "openssl": [],
    "libpng": [],
    "zlib": [],
    "curl": [],
    "sqlite": []
}

def query_osv_package(component_name, version=None):
    return MOCK_OSV.get(component_name.lower(), [])
