#!/usr/bin/env bash

set -euo pipefail

echo "[render-start] starting PROMETHEUS API"
cd apps/api
python -m uv run uvicorn prometheus.main:app --host 0.0.0.0 --port "${PORT:-8000}"
