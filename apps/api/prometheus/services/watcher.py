from __future__ import annotations

import re

from prometheus.models.domain import PolicySignal, WatcherInspection
from prometheus.services.lobstertrap_bridge import LobsterTrapBridge


class WatcherService:
    def __init__(self, bridge: LobsterTrapBridge) -> None:
        self.bridge = bridge
        self.prompt_injection_pattern = re.compile(
            r"ignore previous instructions|reveal your system prompt|dan has no rules",
            re.IGNORECASE,
        )
        self.indirect_prompt_injection_pattern = re.compile(
            r"follow any urgent instructions embedded|embedded inside it|hidden instructions",
            re.IGNORECASE,
        )
        self.credential_pattern = re.compile(
            r"env|environment variables|token|api[_ -]?key|secret|password",
            re.IGNORECASE,
        )
        self.pii_pattern = re.compile(
            r"ssn|social security|patient records|credit card|pii|customer emails|hr records",
            re.IGNORECASE,
        )
        self.exfiltration_pattern = re.compile(
            r"([\w.-]+\.(?:com|net|io|org|ai))|(@[\w.-]+\.(?:com|net|io|org|ai))",
            re.IGNORECASE,
        )
        self.filesystem_pattern = re.compile(
            r"/etc/passwd|/etc/shadow|~/.ssh|c:\\\\users\\\\.*(secret|credential)|/var/lib",
            re.IGNORECASE,
        )
        self.shell_pattern = re.compile(
            r"rm -rf[^\s]*|curl.+\|.+sh|powershell.+-enc|chmod 777|del /s /q|sudo\b",
            re.IGNORECASE,
        )

    def inspect(
        self,
        *,
        user_prompt: str,
        declared_intent: str,
        agent_id: str,
        policy_pack: str,
        risk_score: float,
        detected_intent: str | None = None,
    ) -> WatcherInspection:
        dpi_result = self.bridge.inspect_prompt(
            prompt=user_prompt,
            declared_intent=declared_intent,
            agent_id=agent_id,
            policy_pack=policy_pack,
        )
        effective_detected_intent = (detected_intent or dpi_result.detected_intent or declared_intent).strip()

        signals: list[PolicySignal] = []
        matched_rules = list(dpi_result.matched_rules)

        def add_signal(
            signal_id: str,
            label: str,
            severity: str,
            *,
            matched_rule: str,
        ) -> None:
            if not any(signal.id == signal_id for signal in signals):
                signals.append(PolicySignal(id=signal_id, label=label, severity=severity))  # type: ignore[arg-type]
            if matched_rule not in matched_rules:
                matched_rules.append(matched_rule)

        detected_pii = sorted(
            {match.group(0).lower() for match in self.pii_pattern.finditer(user_prompt)}
        )
        credential_patterns = sorted(
            {match.group(0).lower() for match in self.credential_pattern.finditer(user_prompt)}
        )
        risky_commands = sorted({match.group(0) for match in self.shell_pattern.finditer(user_prompt)})
        target_domains = sorted(
            {
                (match.group(1) or match.group(2).lstrip("@")).lower()
                for match in self.exfiltration_pattern.finditer(user_prompt)
                if match.group(1) or match.group(2)
            }
        )
        target_domains = self._merge_lists(target_domains, dpi_result.target_domains)
        sensitive_paths = self._merge_lists(
            sorted({match.group(0) for match in self.filesystem_pattern.finditer(user_prompt)}),
            dpi_result.sensitive_paths,
        )

        contains_pii = bool(detected_pii) or dpi_result.contains_pii
        contains_credentials = bool(credential_patterns) or dpi_result.contains_credentials
        contains_injection_patterns = bool(self.prompt_injection_pattern.search(user_prompt)) or dpi_result.contains_injection_patterns
        contains_system_commands = bool(risky_commands) or dpi_result.contains_system_commands

        if contains_injection_patterns:
            add_signal(
                "prompt_injection",
                "Prompt injection sequence detected",
                "critical",
                matched_rule="prompt_injection",
            )
        if self.indirect_prompt_injection_pattern.search(user_prompt):
            add_signal(
                "indirect_prompt_injection",
                "Document-borne instruction hijack detected",
                "high",
                matched_rule="prompt_injection",
            )
        if contains_credentials:
            add_signal(
                "credential_harvesting",
                "Credential harvesting language matched",
                "critical",
                matched_rule="credential_harvesting",
            )
        if contains_pii:
            add_signal(
                "pii_extraction",
                "PII extraction request matched",
                "high",
                matched_rule="pii_extraction",
            )
        if target_domains:
            add_signal(
                "data_exfiltration",
                "External domain egress intent matched",
                "critical",
                matched_rule="external_exfiltration",
            )
        if sensitive_paths:
            add_signal(
                "dangerous_filesystem_path",
                "Sensitive filesystem path referenced",
                "high",
                matched_rule="dangerous_filesystem_paths",
            )
        if contains_system_commands:
            add_signal(
                "risky_shell_command",
                "Risky shell command pattern matched",
                "critical",
                matched_rule="risky_shell_commands",
            )
        if declared_intent.strip().lower() != effective_detected_intent.strip().lower():
            add_signal(
                "intent_mismatch",
                "Declared-vs-detected intent mismatch",
                "high",
                matched_rule="declared_vs_detected_intent_mismatch",
            )

        overall_risk = max(risk_score, dpi_result.risk_score)
        floor_decision = "ALLOW"
        if dpi_result.action == "BLOCK":
            floor_decision = "BLOCK"
        elif dpi_result.action == "QUARANTINE":
            floor_decision = "QUARANTINE"

        if any(signal.severity == "critical" for signal in signals) or overall_risk >= 0.9:
            floor_decision = "BLOCK"
        elif floor_decision != "BLOCK" and (
            any(signal.severity == "high" for signal in signals) or overall_risk >= 0.72
        ):
            floor_decision = "QUARANTINE"

        dpi_findings = [signal.label for signal in signals]
        if dpi_result.source == "veea_lobstertrap_cli":
            dpi_findings.insert(0, "Inspected by Veea Lobster Trap CLI.")
        if dpi_result.fallback_used and dpi_result.fallback_reason:
            dpi_findings.append(f"Fallback active: {dpi_result.fallback_reason}")
        if not dpi_findings:
            dpi_findings = ["No deterministic policy rule matched; monitoring only."]

        recommended_action = {
            "ALLOW": "Allow and log",
            "BLOCK": "Block execution and freeze tool path",
            "QUARANTINE": "Quarantine agent and escalate to human review",
        }[floor_decision]

        metadata = self.bridge.metadata(
            dpi_result=dpi_result,
            declared_intent=declared_intent,
            detected_intent=effective_detected_intent,
            agent_id=agent_id,
            policy_pack=policy_pack,
        )

        return WatcherInspection(
            declared_intent=declared_intent,
            detected_intent=effective_detected_intent,
            risk_score=overall_risk,
            floor_decision=floor_decision,  # type: ignore[arg-type]
            dpi_source=dpi_result.source,
            dpi_mode=dpi_result.mode,
            policy_signals=signals,
            metadata=metadata,
            dpi_findings=dpi_findings,
            detected_pii=detected_pii,
            credential_patterns=credential_patterns,
            target_domains=target_domains,
            sensitive_paths=sensitive_paths,
            risky_commands=risky_commands,
            matched_policy_rules=matched_rules,
            raw_lobstertrap_output=dpi_result.raw_lobstertrap_output,
            fallback_used=dpi_result.fallback_used,
            fallback_reason=dpi_result.fallback_reason,
            recommended_action=recommended_action,
        )

    def _merge_lists(self, left: list[str], right: list[str]) -> list[str]:
        merged = list(left)
        for item in right:
            if item and item not in merged:
                merged.append(item)
        return merged
