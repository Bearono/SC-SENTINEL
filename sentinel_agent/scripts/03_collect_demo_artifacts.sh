#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="${1:-/mnt/vmshare/sentinel}"
cd "$PROJECT_ROOT"

echo "=== SENTINEL Part 6: Collect demo artifacts ==="

python3 tools/collect_demo_artifacts.py \
  --project-root "$PROJECT_ROOT" \
  --output-dir demo_artifacts

echo
echo "[INFO] Demo artifact package generated:"
ls -lh demo_artifacts
