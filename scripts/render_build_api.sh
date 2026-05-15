#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

cd "${ROOT_DIR}"

echo "[render-build] pwd: $(pwd)"
python --version

echo "[render-build] upgrading pip"
python -m pip install --upgrade pip

echo "[render-build] installing uv"
python -m pip install --upgrade uv

echo "[render-build] uv version"
python -m uv --version

echo "[render-build] syncing API dependencies"
cd apps/api
python -m uv sync --frozen --no-dev || python -m uv sync --no-dev
cd ../..

echo "[render-build] checking Lobster Trap policy"
ls -la infra/lobstertrap || true

echo "[render-build] attempting Lobster Trap build"
mkdir -p tools

if [ ! -d "tools/lobstertrap" ]; then
  git clone https://github.com/veeainc/lobstertrap.git tools/lobstertrap || echo "[render-build] warning: could not clone Lobster Trap"
fi

if [ -d "tools/lobstertrap" ]; then
  cd tools/lobstertrap
  if command -v make >/dev/null 2>&1; then
    make build || echo "[render-build] warning: Lobster Trap build failed; app will use fallback if binary is unavailable"
  else
    echo "[render-build] warning: make not found; skipping Lobster Trap build"
  fi
  cd ../..
fi

echo "[render-build] final Lobster Trap binary check"
ls -la tools/lobstertrap || true
find tools/lobstertrap -maxdepth 2 -type f -name "lobstertrap" -print || true

echo "[render-build] build complete"
