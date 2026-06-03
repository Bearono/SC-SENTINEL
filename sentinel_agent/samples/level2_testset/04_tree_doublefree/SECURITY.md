# Security Policy — astlite

## Known Vulnerabilities

| ID      | CWE     | Location                              | Notes                              |
|---------|---------|---------------------------------------|------------------------------------|
| AST-007 | CWE-415 | `src/ast_tree.c::ast_node_free`       | Shared-child double-free pattern   |

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.2.x   | :white_check_mark: |
