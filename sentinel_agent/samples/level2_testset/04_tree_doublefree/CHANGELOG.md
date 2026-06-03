# Changelog — astlite

## [0.2.0] - 2025-04-01
### Added
- `ast_node_replace()` and `ast_node_detach_child()` for in-place
  rewrites.

### Known Issues
- **Double free** in `ast_node_free()` when nodes are shared between
  multiple parents (e.g. after `ast_node_move_child()` followed by
  free of both parents). Tracking as `AST-007`.

## [0.1.0] - 2025-01-22
### Added
- Initial release of the astlite allocator and serializer.
