#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

if command -v python3.11 >/dev/null 2>&1; then
  exec python3.11 run_demo.py "$@"
fi

exec python3 run_demo.py "$@"
