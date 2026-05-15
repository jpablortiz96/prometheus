#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
API_DIR="${ROOT_DIR}/apps/api"
TOOLS_DIR="${ROOT_DIR}/tools"
LOBSTERTRAP_DIR="${TOOLS_DIR}/lobstertrap"
LOBSTERTRAP_BIN="${LOBSTERTRAP_DIR}/lobstertrap"
POLICY_PATH="${ROOT_DIR}/infra/lobstertrap/prometheus_policy.yaml"

log() {
  printf '[render-build] %s\n' "$*"
}

warn() {
  printf '[render-build][warn] %s\n' "$*" >&2
}

install_uv() {
  if command -v uv >/dev/null 2>&1; then
    return 0
  fi

  log "Installing uv"
  if command -v python3 >/dev/null 2>&1; then
    python3 -m pip install --user uv
  else
    python -m pip install --user uv
  fi
}

prepare_lobstertrap() {
  mkdir -p "${TOOLS_DIR}"

  if [[ ! -d "${LOBSTERTRAP_DIR}" ]]; then
    if command -v git >/dev/null 2>&1; then
      log "Cloning Lobster Trap source"
      if ! git clone https://github.com/veeainc/lobstertrap.git "${LOBSTERTRAP_DIR}"; then
        warn "Failed to clone Lobster Trap from veeainc/lobstertrap. PROMETHEUS will fall back safely if the binary is unavailable."
        return 0
      fi
    else
      warn "git is not available. Skipping Lobster Trap clone."
      return 0
    fi
  fi

  if [[ ! -f "${LOBSTERTRAP_DIR}/Makefile" ]]; then
    warn "Lobster Trap source is present but Makefile is missing. Skipping build."
    return 0
  fi

  if ! command -v make >/dev/null 2>&1; then
    warn "make is not available. Skipping Lobster Trap build."
    return 0
  fi

  if ! command -v go >/dev/null 2>&1; then
    warn "Go is not available. Skipping Lobster Trap build."
    return 0
  fi

  log "Building Lobster Trap for Linux"
  if ! (cd "${LOBSTERTRAP_DIR}" && make build); then
    warn "Lobster Trap build failed. PROMETHEUS will still boot and use deterministic fallback if the binary is unavailable."
    return 0
  fi

  chmod +x "${LOBSTERTRAP_BIN}" || true
}

main() {
  cd "${ROOT_DIR}"

  export PATH="${HOME}/.local/bin:${PATH}"
  install_uv

  log "pwd: $(pwd)"
  if command -v python3 >/dev/null 2>&1; then
    python3 --version
  else
    python --version
  fi
  uv --version

  log "Syncing backend dependencies"
  (cd "${API_DIR}" && uv sync)

  prepare_lobstertrap

  log "Lobster Trap binary present: $(if [[ -x "${LOBSTERTRAP_BIN}" ]]; then echo yes; else echo no; fi)"
  log "Lobster Trap binary path: ${LOBSTERTRAP_BIN}"
  log "Policy file present: $(if [[ -f "${POLICY_PATH}" ]]; then echo yes; else echo no; fi)"
  log "Policy file path: ${POLICY_PATH}"
}

main "$@"
