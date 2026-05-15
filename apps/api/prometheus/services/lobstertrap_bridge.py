from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from prometheus.core.config import ROOT_DIR, Settings
from prometheus.models.domain import (
    IntegrationStatus,
    LobsterTrapDebugResponse,
    NormalizedDPIResult,
)


@dataclass
class CliCommandResult:
    args: list[str]
    returncode: int | None
    stdout: str
    stderr: str
    elapsed_ms: int | None
    timed_out: bool = False


class LobsterTrapBridge:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.bin_path = self._resolve_binary_path(settings.lobstertrap_bin)
        self.policy_path = self._resolve_file_path(
            settings.lobstertrap_policy_path,
            add_windows_suffix=False,
        )
        self._policy_document: dict[str, Any] | None = None
        self._last_error: str | None = None
        self._last_execution_time_ms: int | None = None
        self._domain_pattern = re.compile(
            r"@([a-z0-9.-]+\.[a-z]{2,})|https?://([a-z0-9.-]+\.[a-z]{2,})", re.I
        )
        self._url_pattern = re.compile(
            r"https?://[^\s]+|(?:[a-z0-9-]+\.)+(?:com|net|io|org|ai|app|dev|co|biz)\b",
            re.I,
        )
        self._pii_pattern = re.compile(
            r"ssn|social security|patient records|credit card|pii|customer emails|hr records",
            re.I,
        )
        self._credential_pattern = re.compile(
            r"env|environment variables|token|api[_ -]?key|secret|password|credential",
            re.I,
        )
        self._injection_pattern = re.compile(
            r"ignore previous instructions|reveal your system prompt|dan has no rules|follow hidden instructions",
            re.I,
        )
        self._system_command_pattern = re.compile(
            r"rm -rf[^\s]*|curl.+\|.+sh|powershell.+-enc|chmod 777|del /s /q|sudo\b|bash\b",
            re.I,
        )
        self._sensitive_path_pattern = re.compile(
            r"(/etc/[^\s]+|~/.ssh(?:/[^\s]+)?|/var/lib(?:/[^\s]+)?|[a-z]:\\[^\r\n]*(?:secret|credential)[^\r\n]*)",
            re.I,
        )
        self._exfiltration_verb_pattern = re.compile(
            r"\b(send|export|upload|email|post|share|sync|transfer)\b",
            re.I,
        )

    @property
    def enabled(self) -> bool:
        return self.settings.lobstertrap_enabled

    @property
    def bin_found(self) -> bool:
        return self.bin_path is not None and self.bin_path.is_file()

    @property
    def bin_executable(self) -> bool:
        return self.bin_found and self._is_executable(self.bin_path)

    @property
    def policy_file_found(self) -> bool:
        return self.policy_path is not None and self.policy_path.exists()

    @property
    def cli_available(self) -> bool:
        return self.enabled and self.bin_executable and self.policy_file_found

    @property
    def mode(self) -> str:
        if not self.enabled:
            return "simulated"
        if self.cli_available:
            return "live_cli"
        return "configured_but_unavailable"

    @property
    def status_label(self) -> str:
        if self.mode == "live_cli":
            return "Veea Lobster Trap DPI floor: LIVE CLI"
        if self.enabled:
            return "Veea Lobster Trap configured · fallback active"
        return "Veea Lobster Trap simulated"

    @property
    def last_error(self) -> str | None:
        return self._status_error()

    @property
    def policy_document(self) -> dict[str, Any]:
        if self._policy_document is not None:
            return self._policy_document
        if not self.policy_file_found or self.policy_path is None:
            self._policy_document = {}
            return self._policy_document
        try:
            self._policy_document = yaml.safe_load(
                self.policy_path.read_text(encoding="utf-8")
            ) or {}
        except Exception:
            self._policy_document = {}
        return self._policy_document

    @property
    def policy_name(self) -> str:
        document = self.policy_document
        for key in ("policy_name", "name"):
            value = document.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        return "prometheus-policy"

    @property
    def policy_rule_count(self) -> int:
        document = self.policy_document
        total = 0
        for key in ("rules", "ingress_rules", "egress_rules"):
            rules = document.get(key)
            if isinstance(rules, list):
                total += len(rules)
        return total

    def inspect_prompt(
        self,
        *,
        prompt: str,
        declared_intent: str,
        agent_id: str,
        policy_pack: str,
    ) -> NormalizedDPIResult:
        fallback_reason = self._status_error()
        if self.mode != "live_cli":
            return self._simulate_result(
                prompt=prompt,
                declared_intent=declared_intent,
                agent_id=agent_id,
                policy_pack=policy_pack,
                fallback_reason=fallback_reason or "Lobster Trap live CLI is not enabled.",
            )

        assert self.policy_path is not None
        result = self._run_cli_command(
            ["inspect", "--policy", str(self.policy_path), prompt]
        )
        self._last_execution_time_ms = result.elapsed_ms
        raw_output = self._combine_output(result.stdout, result.stderr)

        if result.timed_out:
            self._last_error = (
                f"Lobster Trap CLI timed out after {self.settings.lobstertrap_timeout_seconds}s."
            )
            return self._cli_error_result(
                prompt=prompt,
                declared_intent=declared_intent,
                agent_id=agent_id,
                policy_pack=policy_pack,
                fallback_reason=self._status_error() or "Lobster Trap CLI inspection timed out.",
                raw_output=raw_output,
            )

        if result.returncode != 0:
            stderr_preview = self._truncate_text(result.stderr.strip() or result.stdout.strip(), 320)
            self._last_error = (
                f"Lobster Trap CLI exited with code {result.returncode}."
                + (f" {stderr_preview}" if stderr_preview else "")
            ).strip()
            return self._cli_error_result(
                prompt=prompt,
                declared_intent=declared_intent,
                agent_id=agent_id,
                policy_pack=policy_pack,
                fallback_reason=self._status_error() or "Lobster Trap CLI inspection failed.",
                raw_output=raw_output,
            )

        self._last_error = None
        return self._parse_live_result(
            prompt=prompt,
            declared_intent=declared_intent,
            policy_pack=policy_pack,
            raw_output=raw_output,
            stdout=result.stdout,
            stderr=result.stderr,
        )

    def metadata(
        self,
        *,
        dpi_result: NormalizedDPIResult,
        declared_intent: str,
        detected_intent: str,
        agent_id: str,
        policy_pack: str,
    ) -> dict[str, Any]:
        return {
            "_lobstertrap": {
                "source": dpi_result.source,
                "mode": dpi_result.mode,
                "status_mode": self.mode,
                "enabled": self.enabled,
                "available": self.cli_available,
                "fallback_used": dpi_result.fallback_used,
                "fallback_reason": dpi_result.fallback_reason,
                "agent_id": agent_id,
                "policy_pack": policy_pack,
                "policy_name": self.policy_name,
                "policy_file": self._display_path(self.policy_path),
                "policy_file_found": self.policy_file_found,
                "policy_rule_count": self.policy_rule_count,
                "cli_execution_time_ms": self._last_execution_time_ms,
                "lobstertrap_bin": self._display_path(self.bin_path),
                "lobstertrap_bin_found": self.bin_found,
                "declared_intent": declared_intent,
                "detected_intent": detected_intent,
                "verdict": dpi_result.verdict,
                "action": dpi_result.action,
                "risk_score": dpi_result.risk_score,
                "matched_rules": dpi_result.matched_rules,
                "contains_pii": dpi_result.contains_pii,
                "contains_credentials": dpi_result.contains_credentials,
                "contains_injection_patterns": dpi_result.contains_injection_patterns,
                "contains_system_commands": dpi_result.contains_system_commands,
                "contains_urls": dpi_result.contains_urls,
                "target_domains": dpi_result.target_domains,
                "sensitive_paths": dpi_result.sensitive_paths,
                "raw_lobstertrap_output": dpi_result.raw_lobstertrap_output,
                "last_error": self.last_error,
            }
        }

    def status(
        self,
        *,
        gemini_configured: bool,
        gemini_available: bool,
        gemini_last_error: str | None,
        active_policy_pack: str,
        database_available: bool,
    ) -> IntegrationStatus:
        return IntegrationStatus(
            gemini_configured=gemini_configured,
            gemini_connected=gemini_available,
            gemini_available=gemini_available,
            gemini_mode="connected" if gemini_available else "simulated",
            gemini_reasoning_model=self.settings.gemini_reasoning_model,
            gemini_fast_model=self.settings.gemini_fast_model,
            gemini_lite_model=self.settings.gemini_lite_model,
            gemini_last_error=self._sanitize_gemini_error(
                gemini_last_error,
                gemini_configured=gemini_configured,
                gemini_available=gemini_available,
            ),
            lobster_trap_enabled=self.enabled,
            lobster_trap_available=self.cli_available,
            lobster_trap_bin_found=self.bin_found,
            lobster_trap_mode=self.mode,  # type: ignore[arg-type]
            lobster_trap_bin_path=self._display_path(self.bin_path),
            lobster_trap_policy_path=self._display_path(self.policy_path),
            lobster_trap_last_error=self.last_error,
            policy_file_found=self.policy_file_found,
            policy_rule_count=self.policy_rule_count,
            policy_rules_count=self.policy_rule_count,
            demo_fallback_active=not gemini_available,
            audit_trail_online=True,
            database_available=database_available,
            active_policy_pack=active_policy_pack,
            models={
                "reasoning": self.settings.gemini_reasoning_model,
                "fast": self.settings.gemini_fast_model,
                "lite": self.settings.gemini_lite_model,
            },
        )

    def debug_info(self) -> LobsterTrapDebugResponse:
        version_result = (
            self._run_cli_command(["version"])
            if self.bin_executable
            else CliCommandResult([], None, "", "", None)
        )
        inspect_result = (
            self._run_cli_command(
                [
                    "inspect",
                    "--policy",
                    str(self.policy_path),
                    "PROMETHEUS debug prompt",
                ]
            )
            if self.bin_executable and self.policy_path is not None
            else CliCommandResult([], None, "", "", None)
        )
        return LobsterTrapDebugResponse(
            enabled=self.enabled,
            available=self.cli_available,
            mode=self.mode,
            bin_path=str(self.bin_path) if self.bin_path else "",
            bin_exists=self.bin_found,
            bin_is_file=self.bin_found,
            policy_path=str(self.policy_path) if self.policy_path else "",
            policy_exists=self.policy_file_found,
            policy_rules_count=self.policy_rule_count,
            version_returncode=version_result.returncode,
            version_stdout_preview=self._truncate_text(version_result.stdout.strip(), 500),
            version_stderr_preview=self._truncate_text(version_result.stderr.strip(), 500),
            version_elapsed_ms=version_result.elapsed_ms,
            inspect_test_returncode=inspect_result.returncode,
            inspect_test_stdout_preview=self._truncate_text(inspect_result.stdout.strip(), 800),
            inspect_test_stderr_preview=self._truncate_text(inspect_result.stderr.strip(), 800),
            inspect_test_elapsed_ms=inspect_result.elapsed_ms,
            last_error=self._status_error(debug=True),
        )

    def _status_error(self, *, debug: bool = False) -> str | None:
        if not self.enabled:
            return None
        if not self.settings.lobstertrap_bin.strip():
            return "LOBSTERTRAP_BIN is empty." if debug else "LOBSTERTRAP_BIN is not configured."
        if not self.bin_found:
            return (
                f"Lobster Trap binary not found: {self.settings.lobstertrap_bin}"
                if debug
                else "Lobster Trap binary not found."
            )
        if not self.bin_executable:
            return (
                f"Lobster Trap binary is not executable: {self.bin_path}"
                if debug
                else "Lobster Trap binary is not executable."
            )
        if not self.settings.lobstertrap_policy_path.strip():
            return (
                "LOBSTERTRAP_POLICY_PATH is empty."
                if debug
                else "LOBSTERTRAP_POLICY_PATH is not configured."
            )
        if not self.policy_file_found:
            return (
                f"Lobster Trap policy file not found: {self.settings.lobstertrap_policy_path}"
                if debug
                else "Lobster Trap policy file not found."
            )
        if debug:
            return self._truncate_text(self._last_error, 320)
        return "Lobster Trap CLI unavailable. Deterministic fallback is active." if self._last_error else None

    def _resolve_binary_path(self, configured_path: str) -> Path | None:
        if not configured_path.strip():
            return None
        direct = shutil.which(configured_path)
        if direct:
            return Path(direct).resolve()
        return self._resolve_file_path(
            configured_path,
            add_windows_suffix=True,
        )

    def _resolve_file_path(
        self,
        configured_path: str,
        *,
        add_windows_suffix: bool,
    ) -> Path | None:
        if not configured_path.strip():
            return None
        resolved = self.settings.resolve_repo_path(configured_path, prefer_root=True)
        if resolved is None:
            return None
        return self._resolve_windows_variant(resolved, add_windows_suffix) or resolved

    def _resolve_windows_variant(
        self,
        candidate: Path,
        add_windows_suffix: bool,
    ) -> Path | None:
        if not add_windows_suffix or os.name != "nt":
            return None
        if candidate.suffix.lower() == ".exe":
            return candidate.resolve()
        variant = candidate.with_suffix(
            f"{candidate.suffix}.exe" if candidate.suffix else ".exe"
        ).resolve()
        if variant.exists():
            return variant
        return candidate.resolve()

    def _is_executable(self, path: Path | None) -> bool:
        if path is None or not path.is_file():
            return False
        if os.name == "nt":
            return True
        return os.access(path, os.X_OK)

    def _run_cli_command(self, args: list[str]) -> CliCommandResult:
        if self.bin_path is None:
            return CliCommandResult(args=[], returncode=None, stdout="", stderr="", elapsed_ms=None)

        command = [str(self.bin_path), *args]
        started = time.perf_counter()
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=max(self.settings.lobstertrap_timeout_seconds, 1),
                check=False,
                shell=False,
            )
            elapsed_ms = int((time.perf_counter() - started) * 1000)
            return CliCommandResult(
                args=command,
                returncode=result.returncode,
                stdout=self._coerce_text(result.stdout),
                stderr=self._coerce_text(result.stderr),
                elapsed_ms=elapsed_ms,
            )
        except subprocess.TimeoutExpired as exc:
            elapsed_ms = int((time.perf_counter() - started) * 1000)
            return CliCommandResult(
                args=command,
                returncode=None,
                stdout=self._coerce_text(exc.stdout),
                stderr=self._coerce_text(exc.stderr),
                elapsed_ms=elapsed_ms,
                timed_out=True,
            )
        except Exception as exc:
            elapsed_ms = int((time.perf_counter() - started) * 1000)
            return CliCommandResult(
                args=command,
                returncode=None,
                stdout="",
                stderr=str(exc),
                elapsed_ms=elapsed_ms,
            )

    def _display_path(self, path: Path | None) -> str:
        if path is None:
            return ""
        resolved = path.resolve()
        if self.settings.integration_status_debug:
            return str(resolved)
        try:
            return resolved.relative_to(ROOT_DIR.resolve()).as_posix()
        except ValueError:
            return resolved.name

    def _sanitize_gemini_error(
        self,
        error: str | None,
        *,
        gemini_configured: bool,
        gemini_available: bool,
    ) -> str | None:
        if gemini_available or not gemini_configured or error is None:
            return None
        if self.settings.integration_status_debug:
            return self._truncate_text(error, 320)
        return "Gemini backend validation failed. Deterministic fallback is active."

    def _combine_output(self, stdout: str, stderr: str) -> str | None:
        parts = [part.strip() for part in (stdout, stderr) if part and part.strip()]
        return "\n".join(parts) if parts else None

    def _parse_live_result(
        self,
        *,
        prompt: str,
        declared_intent: str,
        policy_pack: str,
        raw_output: str | None,
        stdout: str,
        stderr: str,
    ) -> NormalizedDPIResult:
        payload = self._extract_json(stdout) or self._extract_json(stderr)
        heuristics = self._heuristics(prompt, declared_intent)

        matched_rules = heuristics["matched_rules"]
        risk_score = heuristics["risk_score"]
        detected_intent = heuristics["detected_intent"]
        verdict = heuristics["verdict"]
        action = self._normalize_action(verdict)
        contains_pii = heuristics["contains_pii"]
        contains_credentials = heuristics["contains_credentials"]
        contains_injection_patterns = heuristics["contains_injection_patterns"]
        contains_system_commands = heuristics["contains_system_commands"]
        contains_urls = heuristics["contains_urls"]
        target_domains = heuristics["target_domains"]
        sensitive_paths = heuristics["sensitive_paths"]

        if payload:
            matched_rules = self._merge_lists(
                matched_rules,
                self._extract_list(
                    payload,
                    (
                        "matched_rules",
                        "matchedRules",
                        "rule_matches",
                        "ruleMatches",
                    ),
                ),
            )
            risk_score = (
                self._extract_float(payload, ("risk_score", "riskScore", "metadata.risk_score"))
                or risk_score
            )
            verdict = (
                self._extract_text(payload, ("decision", "verdict", "action", "policy_decision"))
                or verdict
            )
            action = self._normalize_action(verdict)
            detected_intent = self._extract_text(
                payload,
                (
                    "detected_intent",
                    "detectedIntent",
                    "intent_category",
                    "intentCategory",
                ),
            ) or detected_intent
            parsed_contains_pii = self._extract_bool(payload, ("contains_pii", "containsPii"))
            if parsed_contains_pii is not None:
                contains_pii = parsed_contains_pii
            parsed_contains_credentials = self._extract_bool(
                payload,
                ("contains_credentials", "containsCredentials"),
            )
            if parsed_contains_credentials is not None:
                contains_credentials = parsed_contains_credentials
            parsed_contains_injection_patterns = self._extract_bool(
                payload,
                ("contains_injection_patterns", "containsInjectionPatterns"),
            )
            if parsed_contains_injection_patterns is not None:
                contains_injection_patterns = parsed_contains_injection_patterns
            parsed_contains_system_commands = self._extract_bool(
                payload,
                ("contains_system_commands", "containsSystemCommands"),
            )
            if parsed_contains_system_commands is not None:
                contains_system_commands = parsed_contains_system_commands
            parsed_contains_urls = self._extract_bool(payload, ("contains_urls", "containsUrls"))
            if parsed_contains_urls is not None:
                contains_urls = parsed_contains_urls
            target_domains = self._merge_lists(
                target_domains,
                self._extract_list(payload, ("target_domains", "targetDomains", "domains")),
            )
            sensitive_paths = self._merge_lists(
                sensitive_paths,
                self._extract_list(payload, ("sensitive_paths", "sensitivePaths", "paths")),
            )
        else:
            parsed_text = self._parse_text_output(raw_output or "")
            matched_rules = self._merge_lists(matched_rules, parsed_text["matched_rules"])
            risk_score = (
                parsed_text["risk_score"] if parsed_text["risk_score"] is not None else risk_score
            )
            verdict = parsed_text["verdict"] or verdict
            action = self._normalize_action(verdict)
            detected_intent = parsed_text["detected_intent"] or detected_intent
            contains_pii = (
                parsed_text["contains_pii"] if parsed_text["contains_pii"] is not None else contains_pii
            )
            contains_credentials = (
                parsed_text["contains_credentials"]
                if parsed_text["contains_credentials"] is not None
                else contains_credentials
            )
            contains_injection_patterns = (
                parsed_text["contains_injection_patterns"]
                if parsed_text["contains_injection_patterns"] is not None
                else contains_injection_patterns
            )
            contains_system_commands = (
                parsed_text["contains_system_commands"]
                if parsed_text["contains_system_commands"] is not None
                else contains_system_commands
            )
            contains_urls = (
                parsed_text["contains_urls"] if parsed_text["contains_urls"] is not None else contains_urls
            )
            target_domains = self._merge_lists(target_domains, parsed_text["target_domains"])
            sensitive_paths = self._merge_lists(sensitive_paths, parsed_text["sensitive_paths"])

        if (
            self._is_generic_intent(detected_intent)
            and risk_score <= 0.2
            and not matched_rules
        ):
            detected_intent = declared_intent.strip() or detected_intent

        return NormalizedDPIResult(
            source="veea_lobstertrap_cli",
            mode="live_cli",
            verdict=verdict.upper(),
            action=action,
            risk_score=max(0.0, min(1.0, risk_score)),
            matched_rules=matched_rules,
            detected_intent=detected_intent,
            contains_pii=contains_pii,
            contains_credentials=contains_credentials,
            contains_injection_patterns=contains_injection_patterns,
            contains_system_commands=contains_system_commands,
            contains_urls=contains_urls,
            target_domains=target_domains,
            sensitive_paths=sensitive_paths,
            raw_lobstertrap_output=raw_output,
            fallback_used=False,
            fallback_reason=None,
        )

    def _simulate_result(
        self,
        *,
        prompt: str,
        declared_intent: str,
        agent_id: str,
        policy_pack: str,
        fallback_reason: str,
        raw_output: str | None = None,
    ) -> NormalizedDPIResult:
        heuristics = self._heuristics(prompt, declared_intent)
        return NormalizedDPIResult(
            source="simulated",
            mode="simulated",
            verdict=heuristics["verdict"].upper(),
            action=self._normalize_action(heuristics["verdict"]),
            risk_score=heuristics["risk_score"],
            matched_rules=heuristics["matched_rules"],
            detected_intent=heuristics["detected_intent"],
            contains_pii=heuristics["contains_pii"],
            contains_credentials=heuristics["contains_credentials"],
            contains_injection_patterns=heuristics["contains_injection_patterns"],
            contains_system_commands=heuristics["contains_system_commands"],
            contains_urls=heuristics["contains_urls"],
            target_domains=heuristics["target_domains"],
            sensitive_paths=heuristics["sensitive_paths"],
            raw_lobstertrap_output=raw_output,
            fallback_used=True,
            fallback_reason=fallback_reason
            or f"Fallback simulation used for {agent_id} in {policy_pack}.",
        )

    def _cli_error_result(
        self,
        *,
        prompt: str,
        declared_intent: str,
        agent_id: str,
        policy_pack: str,
        fallback_reason: str,
        raw_output: str | None,
    ) -> NormalizedDPIResult:
        heuristics = self._heuristics(prompt, declared_intent)
        return NormalizedDPIResult(
            source="veea_lobstertrap_cli",
            mode="live_cli_error",
            verdict=heuristics["verdict"].upper(),
            action=self._normalize_action(heuristics["verdict"]),
            risk_score=heuristics["risk_score"],
            matched_rules=heuristics["matched_rules"],
            detected_intent=heuristics["detected_intent"],
            contains_pii=heuristics["contains_pii"],
            contains_credentials=heuristics["contains_credentials"],
            contains_injection_patterns=heuristics["contains_injection_patterns"],
            contains_system_commands=heuristics["contains_system_commands"],
            contains_urls=heuristics["contains_urls"],
            target_domains=heuristics["target_domains"],
            sensitive_paths=heuristics["sensitive_paths"],
            raw_lobstertrap_output=self._truncate_text(raw_output, 4000),
            fallback_used=True,
            fallback_reason=fallback_reason
            or f"Lobster Trap CLI fallback used for {agent_id} in {policy_pack}.",
        )

    def _heuristics(self, prompt: str, declared_intent: str) -> dict[str, Any]:
        contains_pii = bool(self._pii_pattern.search(prompt))
        contains_credentials = bool(self._credential_pattern.search(prompt))
        contains_injection_patterns = bool(self._injection_pattern.search(prompt))
        contains_system_commands = bool(self._system_command_pattern.search(prompt))
        sensitive_paths = sorted(
            {match.group(0) for match in self._sensitive_path_pattern.finditer(prompt)}
        )
        target_domains = self._extract_domains(prompt)
        contains_urls = bool(target_domains or self._url_pattern.search(prompt))

        matched_rules: list[str] = []
        if contains_injection_patterns:
            matched_rules.append("prompt_injection")
        if contains_credentials:
            matched_rules.append("credential_harvesting")
        if contains_pii:
            matched_rules.append("pii_extraction")
        if target_domains and self._exfiltration_verb_pattern.search(prompt):
            matched_rules.append("external_exfiltration")
        if sensitive_paths:
            matched_rules.append("dangerous_filesystem_paths")
        if contains_system_commands:
            matched_rules.append("risky_shell_commands")

        detected_intent = declared_intent.strip() or "general"
        if contains_credentials:
            detected_intent = "credential access"
        elif contains_pii:
            detected_intent = "regulated data extraction"
        elif target_domains and self._exfiltration_verb_pattern.search(prompt):
            detected_intent = "external data transfer"
        elif contains_system_commands or sensitive_paths:
            detected_intent = "system access"
        elif contains_injection_patterns:
            detected_intent = "prompt injection"

        if declared_intent.strip().lower() != detected_intent.strip().lower():
            matched_rules.append("declared_vs_detected_intent_mismatch")

        weights = {
            "prompt_injection": 0.34,
            "credential_harvesting": 0.32,
            "pii_extraction": 0.3,
            "external_exfiltration": 0.28,
            "dangerous_filesystem_paths": 0.18,
            "risky_shell_commands": 0.24,
            "declared_vs_detected_intent_mismatch": 0.16,
        }
        risk_score = min(0.98, 0.06 + sum(weights.get(rule, 0.1) for rule in matched_rules))

        verdict = "ALLOW"
        if any(
            rule in matched_rules
            for rule in (
                "prompt_injection",
                "credential_harvesting",
                "pii_extraction",
                "external_exfiltration",
                "risky_shell_commands",
            )
        ):
            verdict = "DENY"
        elif matched_rules:
            verdict = "QUARANTINE"

        return {
            "matched_rules": matched_rules,
            "risk_score": risk_score,
            "detected_intent": detected_intent,
            "verdict": verdict,
            "contains_pii": contains_pii,
            "contains_credentials": contains_credentials,
            "contains_injection_patterns": contains_injection_patterns,
            "contains_system_commands": contains_system_commands,
            "contains_urls": contains_urls,
            "target_domains": target_domains,
            "sensitive_paths": sensitive_paths,
        }

    def _extract_domains(self, text: str) -> list[str]:
        domains = set()
        for match in self._domain_pattern.finditer(text):
            candidate = (match.group(1) or match.group(2) or "").lower().strip(".")
            if candidate:
                domains.add(candidate)
        return sorted(domains)

    def _extract_json(self, text: str) -> dict[str, Any] | None:
        payload = text.strip()
        if not payload:
            return None
        try:
            decoded = json.loads(payload)
        except json.JSONDecodeError:
            start = payload.find("{")
            end = payload.rfind("}")
            if start < 0 or end <= start:
                return None
            try:
                decoded = json.loads(payload[start : end + 1])
            except json.JSONDecodeError:
                return None
        return decoded if isinstance(decoded, dict) else None

    def _parse_text_output(self, text: str) -> dict[str, Any]:
        payload = text or ""
        verdict_match = re.search(
            r"(decision|verdict|action)\s*[:=]\s*(ALLOW|DENY|BLOCK|QUARANTINE|HUMAN_REVIEW|LOG)",
            payload,
            re.I,
        )
        risk_match = re.search(r"risk[_ ]score\s*[:=]\s*([0-9.]+)", payload, re.I)
        bool_match = lambda key: re.search(rf"{key}\s*[:=]\s*(true|false)", payload, re.I)  # noqa: E731
        matched_rules = [
            rule_id
            for rule_id in self._policy_rule_ids()
            if re.search(rf"\b{re.escape(rule_id)}\b", payload, re.I)
        ]
        intent_match = re.search(
            r"(detected[_ ]intent|intent[_ ]category)\s*[:=]\s*([^\n\r]+)",
            payload,
            re.I,
        )

        return {
            "verdict": verdict_match.group(2).upper() if verdict_match else None,
            "risk_score": float(risk_match.group(1)) if risk_match else None,
            "contains_pii": self._match_bool(bool_match("contains_pii")),
            "contains_credentials": self._match_bool(bool_match("contains_credentials")),
            "contains_injection_patterns": self._match_bool(
                bool_match("contains_injection_patterns")
            ),
            "contains_system_commands": self._match_bool(
                bool_match("contains_system_commands")
            ),
            "contains_urls": self._match_bool(bool_match("contains_urls")),
            "detected_intent": intent_match.group(2).strip() if intent_match else None,
            "matched_rules": matched_rules,
            "target_domains": self._extract_domains(payload),
            "sensitive_paths": sorted(
                {match.group(0) for match in self._sensitive_path_pattern.finditer(payload)}
            ),
        }

    def _policy_rule_ids(self) -> list[str]:
        ids: list[str] = []
        for key in ("rules", "ingress_rules", "egress_rules"):
            rules = self.policy_document.get(key)
            if not isinstance(rules, list):
                continue
            for rule in rules:
                if not isinstance(rule, dict):
                    continue
                value = rule.get("id") or rule.get("name")
                if isinstance(value, str) and value:
                    ids.append(value)
        return ids

    def _extract_text(self, payload: dict[str, Any], keys: tuple[str, ...]) -> str | None:
        for key in keys:
            value = self._resolve_nested(payload, key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        return None

    def _extract_float(self, payload: dict[str, Any], keys: tuple[str, ...]) -> float | None:
        for key in keys:
            value = self._resolve_nested(payload, key)
            if isinstance(value, (int, float)):
                return float(value)
            if isinstance(value, str):
                try:
                    return float(value)
                except ValueError:
                    continue
        return None

    def _extract_bool(self, payload: dict[str, Any], keys: tuple[str, ...]) -> bool | None:
        for key in keys:
            value = self._resolve_nested(payload, key)
            if isinstance(value, bool):
                return value
            if isinstance(value, str) and value.strip().lower() in {"true", "false"}:
                return value.strip().lower() == "true"
        return None

    def _extract_list(self, payload: dict[str, Any], keys: tuple[str, ...]) -> list[str]:
        extracted: list[str] = []
        for key in keys:
            value = self._resolve_nested(payload, key)
            if isinstance(value, list):
                extracted.extend(str(item).strip() for item in value if str(item).strip())
            elif isinstance(value, str) and value.strip():
                extracted.extend(part.strip() for part in value.split(",") if part.strip())
        return self._merge_lists([], extracted)

    def _resolve_nested(self, payload: dict[str, Any], key: str) -> Any:
        current: Any = payload
        for part in key.split("."):
            if not isinstance(current, dict):
                return None
            current = current.get(part)
        return current

    def _normalize_action(self, verdict: str) -> str:
        normalized = verdict.strip().upper()
        if normalized in {"DENY", "BLOCK"}:
            return "BLOCK"
        if normalized in {"QUARANTINE", "HUMAN_REVIEW", "RATE_LIMIT"}:
            return "QUARANTINE"
        return "ALLOW"

    def _merge_lists(self, primary: list[str], secondary: list[str]) -> list[str]:
        merged = list(primary)
        for item in secondary:
            if item and item not in merged:
                merged.append(item)
        return merged

    def _match_bool(self, match: re.Match[str] | None) -> bool | None:
        if match is None:
            return None
        return match.group(1).lower() == "true"

    def _is_generic_intent(self, value: str) -> bool:
        normalized = value.strip().lower()
        return normalized in {"general", "other", "unknown", "unspecified"}

    def _coerce_text(self, value: str | bytes | None) -> str:
        if value is None:
            return ""
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        return value

    def _truncate_text(self, value: str | None, limit: int) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        if len(normalized) <= limit:
            return normalized
        return f"{normalized[:limit].rstrip()}... [truncated]"
