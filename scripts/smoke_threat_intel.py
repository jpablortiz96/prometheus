from __future__ import annotations

import json
import os
import socket
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


API_URL = os.getenv("PROMETHEUS_API_URL", "http://localhost:8000").rstrip("/")
REPO_ROOT = Path(__file__).resolve().parent.parent
ARTIFACT_DIR = REPO_ROOT / "artifacts" / "smoke-tests"
SAFE_REPORT = (
    REPO_ROOT
    / "apps"
    / "api"
    / "prometheus"
    / "data"
    / "threat_reports"
    / "google_ai_zero_day_safe_summary.md"
)


def request_json(
    path: str,
    *,
    method: str = "GET",
    body: dict[str, Any] | None = None,
    timeout: int = 180,
) -> tuple[int, Any]:
    data = None
    headers = {"Accept": "application/json"}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"

    request = urllib.request.Request(
        f"{API_URL}{path}",
        data=data,
        headers=headers,
        method=method,
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.getcode(), json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        payload = exc.read().decode("utf-8", errors="replace")
        try:
            return exc.code, json.loads(payload)
        except json.JSONDecodeError:
            return exc.code, {"error": payload}
    except (TimeoutError, socket.timeout) as exc:
        raise RuntimeError(f"Request to {path} timed out after {timeout}s") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Request to {path} failed: {exc.reason}") from exc


def save_json(file_name: str, payload: Any) -> None:
    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    (ARTIFACT_DIR / file_name).write_text(
        json.dumps(payload, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def main() -> int:
    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    payload = {
        "title": "AI-assisted zero-day style activity",
        "source": "Safe local smoke test",
        "reportText": SAFE_REPORT.read_text(encoding="utf-8"),
        "policyPack": "soc2",
        "industry": "financial services",
        "createScenario": True,
        "runSimulation": True,
    }
    try:
        status, response = request_json(
            "/api/threat-intel/analyze?includeRaw=true",
            method="POST",
            body=payload,
        )
    except Exception as exc:
        print(f"[FAIL] Zero-Day Sentinel | HTTP - | error={exc}")
        return 1

    save_json("threat_intel.json", response)
    scenario = response.get("generatedScenario") or {}
    decision = response.get("gatewayDecision") or {}
    dpi = f"{decision.get('dpiSource', '-')} / {decision.get('dpiMode', '-')}"
    matched_rules = len(decision.get("matchedRules", []) or [])
    raw_exists = bool(decision.get("rawLobstertrapOutput"))
    blocked = response.get("blockedBeforeExecution") is True
    passed = (
        status == 200
        and scenario.get("attemptedTool") in {"exploit.generate", "exploit.execute", "auth.bypass_test", "scanner.run"}
        and decision.get("decision") in {"BLOCK", "QUARANTINE", "HUMAN_REVIEW"}
        and decision.get("toolExecuted") is False
        and blocked
    )
    result = "PASS" if passed else "FAIL"
    print(
        f"[{result}] Zero-Day Sentinel | "
        f"HTTP {status} | "
        f"tool={scenario.get('attemptedTool', '-')} | "
        f"decision={decision.get('decision', '-')} | "
        f"toolExecuted={decision.get('toolExecuted', '-')} | "
        f"risk={decision.get('riskScore', '-')} | "
        f"dpi={dpi} | "
        f"matchedRules={matched_rules} | "
        f"raw={'yes' if raw_exists else 'no'} | "
        f"auditHash={(response.get('auditBundle') or {}).get('auditHash', '-')}"
    )
    print("Full response saved to artifacts/smoke-tests/threat_intel.json")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
