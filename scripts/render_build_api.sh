#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

log() {
  printf '[render-build] %s\n' "$*"
}

warn() {
  printf '[render-build][warn] %s\n' "$*" >&2
}

install_go_if_missing() {
  if command -v go >/dev/null 2>&1; then
    log "Go already available"
    return 0
  fi

  GO_VERSION="${GO_VERSION:-1.23.4}"
  MACHINE_ARCH="$(uname -m)"
  if [ "${MACHINE_ARCH}" = "x86_64" ]; then
    GO_ARCH="amd64"
  elif [ "${MACHINE_ARCH}" = "aarch64" ]; then
    GO_ARCH="arm64"
  else
    warn "unsupported architecture: ${MACHINE_ARCH}; defaulting to amd64"
    GO_ARCH="amd64"
  fi

  log "Go not found. Installing Go ${GO_VERSION} locally for ${GO_ARCH}"
  mkdir -p "${HOME}/.local"

  if ! curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${GO_ARCH}.tar.gz" -o /tmp/go.tar.gz; then
    warn "could not download Go ${GO_VERSION}"
    return 0
  fi

  rm -rf "${HOME}/.local/go"
  if ! tar -C "${HOME}/.local" -xzf /tmp/go.tar.gz; then
    warn "could not extract Go ${GO_VERSION}"
    return 0
  fi

  export PATH="${HOME}/.local/go/bin:${PATH}"
  go version || warn "Go install verification failed"
}

build_lobstertrap() {
  log "checking Lobster Trap policy"
  ls -la infra/lobstertrap || true

  log "attempting Lobster Trap build"
  mkdir -p tools

  if [ ! -d "tools/lobstertrap" ]; then
    git clone https://github.com/veeainc/lobstertrap.git tools/lobstertrap || warn "could not clone Lobster Trap"
  fi

  install_go_if_missing
  export PATH="${HOME}/.local/go/bin:${PATH}"

  if [ -d "tools/lobstertrap" ]; then
    cd tools/lobstertrap
    if command -v make >/dev/null 2>&1; then
      make build || warn "Lobster Trap build failed; app will use fallback if binary is unavailable"
    else
      warn "make not found; skipping Lobster Trap build"
    fi
    cd ../..
  fi

  if [ -f "tools/lobstertrap/lobstertrap" ]; then
    chmod +x tools/lobstertrap/lobstertrap || true
  fi

  log "final Lobster Trap binary check"
  ls -la tools/lobstertrap || true
  find tools/lobstertrap -maxdepth 2 -type f -name "lobstertrap" -print || true
}

main() {
  cd "${ROOT_DIR}"

  log "pwd: $(pwd)"
  python --version

  log "upgrading pip"
  python -m pip install --upgrade pip

  log "installing uv"
  python -m pip install --upgrade uv

  log "uv version"
  python -m uv --version

  log "syncing API dependencies"
  cd apps/api
  python -m uv sync --frozen --no-dev || python -m uv sync --no-dev
  cd ../..

  build_lobstertrap

  log "build complete"
}

main "$@"
