#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
python3 -c 'import sys; assert sys.version_info[:2] == (3, 12), "CPython 3.12 required"'
DAMASCUS_RUN_DIR="runs/local-$(date -u +%Y%m%dT%H%M%SZ)-$$"
python3 -m damascus_a preflight --output "$DAMASCUS_RUN_DIR/preflight.json"
python3 -m damascus_a correctness --d 2 --k 2 --cases 4 --backend cpu-reference --output "$DAMASCUS_RUN_DIR/correctness"
python3 -m damascus_a protocol-correctness --correctness-only --epochs 2 --backend cpu-reference --output "$DAMASCUS_RUN_DIR/protocol-correctness"
