#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
API_DIR="${ROOT_DIR}/apps/api"

cd "${API_DIR}"
exec uv run uvicorn prometheus.main:app --host 0.0.0.0 --port "${PORT:-8000}"
