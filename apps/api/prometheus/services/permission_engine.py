from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from prometheus.models.domain import (
    AgentRecord,
    GatewayPermissionMatrix,
    PermissionEvaluation,
    PermissionMatrixRow,
    ToolCallRequest,
    WatcherInspection,
)
from prometheus.services.sandbox_tools import SandboxToolsService, ToolSpec


class PermissionEngine:
    def __init__(self, tools: SandboxToolsService) -> None:
        self.tools = tools
        self.permissions_path = Path(__file__).resolve().parent.parent / "data" / "permissions.json"
        self._permissions_cache: dict[str, dict[str, list[str]]] | None = None

    @property
    def permissions(self) -> dict[str, dict[str, list[str]]]:
        if self._permissions_cache is None:
            self._permissions_cache = json.loads(
                self.permissions_path.read_text(encoding="utf-8")
            )
        return self._permissions_cache

    def permission_matrix(self, agents: list[AgentRecord]) -> GatewayPermissionMatrix:
        tools = [spec.name for spec in self.tools.catalog()]
        rows: list[PermissionMatrixRow] = []
        for agent in agents:
            cells = {
                tool_name: self._resolve_base_state(agent.id, self.tools.get_spec(tool_name))
                for tool_name in tools
            }
            rows.append(
                PermissionMatrixRow(agent_id=agent.id, agent_name=agent.name, cells=cells)
            )
        return GatewayPermissionMatrix(tools=tools, rows=rows)

    def evaluate(
        self,
        *,
        request: ToolCallRequest,
        tool_spec: ToolSpec,
        inspection: WatcherInspection,
    ) -> PermissionEvaluation:
        base_state = self._resolve_base_state(request.agent_id, tool_spec)
        matched_restrictions: list[str] = []
        permission_state = base_state
        reason = f"{request.agent_id} is permitted to use {request.tool_name}."

        if base_state == "denied":
            matched_restrictions.append("agent_denied_tool")
            permission_state = "denied"
            reason = f"{request.agent_id} is explicitly denied from using {request.tool_name}."
        elif base_state == "quarantine":
            matched_restrictions.append("quarantine_required_tool")
            reason = f"{request.tool_name} is only available behind quarantine controls."
        elif base_state == "human_review":
            matched_restrictions.append("human_review_required_tool")
            reason = f"{request.tool_name} requires human review before execution."

        if request.requires_human_review and permission_state == "allowed":
            permission_state = "human_review"
            matched_restrictions.append("request_marked_human_review")
            reason = "The calling workflow marked this tool call for human review."

        if tool_spec.external_egress and request.policy_pack.lower() in {"finance", "gdpr", "hipaa"}:
            matched_restrictions.append("external_egress_policy_restriction")
            if permission_state == "allowed":
                permission_state = "human_review"
                reason = (
                    f"{request.policy_pack.upper()} policy pack requires additional review for "
                    f"external egress through {request.tool_name}."
                )

        if tool_spec.data_classification in {"legal_privileged", "hr_restricted"} and permission_state == "allowed":
            matched_restrictions.append("sensitive_classification_review")
            permission_state = "human_review"
            reason = (
                f"{tool_spec.data_classification.replace('_', ' ')} workflows require human review "
                f"for {request.tool_name}."
            )

        if request.tool_name == "refund.execute":
            amount = float(request.payload.get("amount", 0) or 0)
            if amount > 250:
                permission_state = "denied"
                matched_restrictions.append("refund_threshold_exceeded")
                reason = f"Refund amount {amount:.2f} exceeds the autonomous execution threshold."

        if request.tool_name in {"exploit.generate", "exploit.execute"}:
            permission_state = "denied"
            matched_restrictions.append("cyber_exploit_workflow_denied")
            reason = f"{request.tool_name} is prohibited in Prometheus and cannot execute."

        if request.tool_name == "auth.bypass_test" and permission_state == "allowed":
            permission_state = "quarantine"
            matched_restrictions.append("identity_bypass_testing_quarantine")
            reason = "Authentication bypass testing must remain quarantined inside the sandbox."

        if request.tool_name == "scanner.run" and permission_state == "allowed":
            permission_state = "human_review"
            matched_restrictions.append("scanner_review_required")
            reason = "Scanner activity requires human review before any simulation can proceed."

        if "declared_vs_detected_intent_mismatch" in inspection.matched_policy_rules and permission_state == "allowed":
            matched_restrictions.append("intent_mismatch_requires_quarantine")
            permission_state = "quarantine"
            reason = "Declared-vs-detected intent mismatch forces the tool path into quarantine."

        if "prompt_injection" in inspection.matched_policy_rules and permission_state == "allowed":
            matched_restrictions.append("prompt_injection_requires_quarantine")
            permission_state = "quarantine"
            reason = "Prompt injection evidence forces the tool path into quarantine."

        return PermissionEvaluation(
            agent_id=request.agent_id,
            tool_name=request.tool_name,
            policy_pack=request.policy_pack,
            permission_state=permission_state,  # type: ignore[arg-type]
            allowed=permission_state == "allowed",
            requires_human_review=permission_state == "human_review",
            external_egress=tool_spec.external_egress,
            data_classification=tool_spec.data_classification,
            reason=reason,
            matched_restrictions=matched_restrictions,
        )

    def _resolve_base_state(self, agent_id: str, tool_spec: ToolSpec) -> str:
        record = self.permissions.get(agent_id, {})
        if tool_spec.name in record.get("denied_tools", []):
            return "denied"
        if tool_spec.name in record.get("quarantine_tools", []):
            return "quarantine"
        if tool_spec.name in record.get("human_review_tools", []):
            return "human_review"
        if tool_spec.name in record.get("allowed_tools", []):
            return "allowed"
        return tool_spec.default_permission_state
