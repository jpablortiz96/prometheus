from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import uuid4

from prometheus.models.domain import (
    AgentRecord,
    PermissionEvaluation,
    Prediction,
    SandboxToolResult,
    Scenario,
    ToolCallDecision,
    ToolCallRequest,
    TribunalDecision,
    WatcherInspection,
)
from prometheus.services.permission_engine import PermissionEngine
from prometheus.services.prophet import ProphetService
from prometheus.services.sandbox_tools import SandboxToolsService, ToolSpec
from prometheus.services.tribunal import TribunalService
from prometheus.services.watcher import WatcherService


@dataclass
class GatewayExecution:
    request: ToolCallRequest
    inspection: WatcherInspection
    prediction: Prediction
    permission_evaluation: PermissionEvaluation
    tribunal_decision: TribunalDecision | None
    tool_result: SandboxToolResult | None
    decision: ToolCallDecision
    scenario: Scenario


class ToolGatewayService:
    def __init__(
        self,
        *,
        watcher: WatcherService,
        prophet: ProphetService,
        tribunal: TribunalService,
        permission_engine: PermissionEngine,
        sandbox_tools: SandboxToolsService,
    ) -> None:
        self.watcher = watcher
        self.prophet = prophet
        self.tribunal = tribunal
        self.permission_engine = permission_engine
        self.sandbox_tools = sandbox_tools

    async def enforce(
        self,
        *,
        request: ToolCallRequest,
        agent: AgentRecord,
        scenario_context: Scenario | None = None,
    ) -> GatewayExecution:
        tool_spec = self.sandbox_tools.get_spec(request.tool_name)
        inspection = self.watcher.inspect(
            user_prompt=request.prompt,
            declared_intent=request.declared_intent,
            agent_id=request.agent_id,
            policy_pack=request.policy_pack,
            risk_score=self._initial_risk(tool_spec, request.prompt),
        )
        permission_evaluation = self.permission_engine.evaluate(
            request=request,
            tool_spec=tool_spec,
            inspection=inspection,
        )
        scenario = self._scenario_from_request(
            request=request,
            agent=agent,
            tool_spec=tool_spec,
            inspection=inspection,
            permission_evaluation=permission_evaluation,
            scenario_context=scenario_context,
        )
        tribunal_decision: TribunalDecision | None = None
        if self._should_short_circuit(request=request, evaluation=permission_evaluation):
            prediction = self._hard_stop_prediction(agent=agent, request=request, inspection=inspection)
        else:
            prediction = await self.prophet.predict(
                agent=agent,
                scenario=scenario,
                inspection=inspection,
            )
            if self._should_run_tribunal(request=request, inspection=inspection, evaluation=permission_evaluation):
                tribunal_decision = await self.tribunal.evaluate(
                    agent=agent,
                    scenario=scenario,
                    inspection=inspection,
                    prediction=prediction,
                )

        final_decision = self._resolve_final_decision(
            permission_evaluation=permission_evaluation,
            inspection=inspection,
            tribunal_decision=tribunal_decision,
        )

        tool_result: SandboxToolResult | None = None
        if final_decision == "ALLOW":
            tool_result = self.sandbox_tools.execute(
                agent_id=request.agent_id,
                tool_name=request.tool_name,
                payload=request.payload,
            )

        request_id = f"gw_{uuid4().hex[:12]}"
        side_effect_prevented = None
        if final_decision != "ALLOW":
            side_effect_prevented = self._prevented_effect(request.tool_name)

        reason = self._reason(
            permission_evaluation=permission_evaluation,
            tribunal_decision=tribunal_decision,
            tool_result=tool_result,
            final_decision=final_decision,
            side_effect_prevented=side_effect_prevented,
        )
        audit_hash = self._audit_hash(
            request_id=request_id,
            request=request,
            inspection=inspection,
            prediction=prediction,
            permission_evaluation=permission_evaluation,
            tribunal_decision=tribunal_decision,
            tool_result=tool_result,
            final_decision=final_decision,
        )

        decision = ToolCallDecision(
            request_id=request_id,
            agent_id=request.agent_id,
            tool_name=request.tool_name,
            declared_intent=request.declared_intent,
            detected_intent=inspection.detected_intent,
            predicted_action=prediction.predicted_action,
            observed_action=request.tool_name,
            dpi_source=inspection.dpi_source,
            dpi_mode=inspection.dpi_mode,
            decision=final_decision,  # type: ignore[arg-type]
            tool_executed=tool_result.executed if tool_result else False,
            risk_score=max(inspection.risk_score, prediction.divergence_score),
            matched_rules=inspection.matched_policy_rules + permission_evaluation.matched_restrictions,
            reason=reason,
            raw_lobstertrap_output=inspection.raw_lobstertrap_output,
            tribunal_votes=tribunal_decision.judges if tribunal_decision else [],
            audit_hash=audit_hash,
            permission_evaluation=permission_evaluation,
            tool_result=tool_result,
            side_effect_prevented=side_effect_prevented,
            side_effect_prevented_flag=side_effect_prevented is not None,
        )

        return GatewayExecution(
            request=request,
            inspection=inspection,
            prediction=prediction,
            permission_evaluation=permission_evaluation,
            tribunal_decision=tribunal_decision,
            tool_result=tool_result,
            decision=decision,
            scenario=scenario,
        )

    def permission_matrix(self, agents: list[AgentRecord]):
        return self.permission_engine.permission_matrix(agents)

    def _initial_risk(self, tool_spec: ToolSpec, prompt: str) -> float:
        risk = 0.18
        if tool_spec.default_permission_state == "human_review":
            risk = 0.46
        elif tool_spec.default_permission_state == "quarantine":
            risk = 0.61
        elif tool_spec.default_permission_state == "denied":
            risk = 0.74
        if tool_spec.external_egress:
            risk += 0.08
        if "hidden instruction" in prompt.lower() or "ignore previous instructions" in prompt.lower():
            risk += 0.12
        return min(risk, 0.95)

    def _scenario_from_request(
        self,
        *,
        request: ToolCallRequest,
        agent: AgentRecord,
        tool_spec: ToolSpec,
        inspection: WatcherInspection,
        permission_evaluation: PermissionEvaluation,
        scenario_context: Scenario | None,
    ) -> Scenario:
        if scenario_context is not None:
            return scenario_context.model_copy(
                update={
                    "user_prompt": request.prompt,
                    "declared_intent": request.declared_intent,
                    "detected_intent": inspection.detected_intent,
                    "agent_id": request.agent_id,
                    "observed_action": request.tool_name,
                    "policy_pack": request.policy_pack,
                }
            )

        baseline_step = agent.baseline.split(" -> ")[0].strip() if agent.baseline else request.tool_name
        expected_decision = {
            "denied": "BLOCK",
            "quarantine": "QUARANTINE",
            "human_review": "QUARANTINE",
            "allowed": "ALLOW",
        }[permission_evaluation.permission_state]
        return Scenario(
            id=f"gateway_{request.tool_name.replace('.', '_')}",
            name=f"Gateway enforcement for {request.tool_name}",
            user_prompt=request.prompt,
            declared_intent=request.declared_intent,
            detected_intent=inspection.detected_intent,
            expected_decision=expected_decision,  # type: ignore[arg-type]
            risk_score=inspection.risk_score,
            policy_pack=request.policy_pack,
            explanation=permission_evaluation.reason,
            agent_id=request.agent_id,
            observed_action=request.tool_name,
            predicted_action=baseline_step,
            mitre_tactic_label=self._mitre_label(tool_spec),
            department=agent.role.title(),
            business_impact=f"{request.tool_name} would operate on {tool_spec.data_classification.replace('_', ' ')} data.",
            regulatory_impact=f"{request.policy_pack.upper()} policy pack governs this {request.tool_name} path.",
            compliance_concern=f"{tool_spec.data_classification.replace('_', ' ')} access control and tool governance.",
            blocked_action=f"{request.tool_name} execution",
            recommended_remediation="Bind tool scopes to least privilege and require review for risky actions.",
            audit_summary=f"PROMETHEUS intercepted {request.tool_name} before it reached enterprise systems.",
            enterprise_value="Prometheus sits in the execution path and prevents unsafe tool calls before execution.",
            affected_resources=[request.tool_name],
        )

    def _mitre_label(self, tool_spec: ToolSpec) -> str:
        if tool_spec.name == "exploit.generate":
            return "TA0042 - Exploit Development Intent"
        if tool_spec.name == "exploit.execute":
            return "TA0043 - Simulated Exploit Execution"
        if tool_spec.name == "auth.bypass_test":
            return "TA0004 - Identity Control Bypass"
        if tool_spec.name == "scanner.run":
            return "TA0041 - Reconnaissance Automation"
        if tool_spec.name == "vuln.research":
            return "TA0040 - Defensive Vulnerability Research"
        if tool_spec.name == "report.write":
            return "TA0039 - Security Reporting"
        if tool_spec.external_egress:
            return "TA0010 - External Egress"
        if tool_spec.data_classification == "legal_privileged":
            return "TA0017 - Contract Integrity Drift"
        if tool_spec.name == "refund.execute":
            return "TA0018 - Workflow Bypass Automation"
        return "TA0005 - Tool Governance"

    def _should_short_circuit(
        self,
        *,
        request: ToolCallRequest,
        evaluation: PermissionEvaluation,
    ) -> bool:
        hard_stop_tools = {
            "exploit.generate",
            "exploit.execute",
            "auth.bypass_test",
            "email.send_external",
            "contracts.rewrite",
            "finance.export_external",
            "crm.export",
            "hr.records.export",
        }
        return request.tool_name in hard_stop_tools and evaluation.permission_state in {
            "denied",
            "human_review",
            "quarantine",
        }

    def _hard_stop_prediction(
        self,
        *,
        agent: AgentRecord,
        request: ToolCallRequest,
        inspection: WatcherInspection,
    ) -> Prediction:
        baseline_step = agent.baseline.split(" -> ")[0].strip() if agent.baseline else request.tool_name
        return Prediction(
            predicted_action=baseline_step,
            divergence_score=max(inspection.risk_score, 0.93),
            confidence=0.99,
            explanation="Explicit hard-stop policy denied the cyber tool before behavioral reasoning was required.",
            model_used="deterministic-hard-stop",
        )

    def _should_run_tribunal(
        self,
        *,
        request: ToolCallRequest,
        inspection: WatcherInspection,
        evaluation: PermissionEvaluation,
    ) -> bool:
        mismatch = request.declared_intent.strip().lower() != inspection.detected_intent.strip().lower()
        return (
            evaluation.permission_state != "allowed"
            or inspection.floor_decision != "ALLOW"
            or inspection.risk_score >= 0.72
            or mismatch
        )

    def _resolve_final_decision(
        self,
        *,
        permission_evaluation: PermissionEvaluation,
        inspection: WatcherInspection,
        tribunal_decision: TribunalDecision | None,
    ) -> str:
        if permission_evaluation.permission_state == "denied" or inspection.floor_decision == "BLOCK":
            base_decision = "BLOCK"
        elif permission_evaluation.permission_state == "quarantine" or inspection.floor_decision == "QUARANTINE":
            base_decision = "QUARANTINE"
        elif permission_evaluation.permission_state == "human_review":
            base_decision = "HUMAN_REVIEW"
        else:
            base_decision = "ALLOW"

        if tribunal_decision is None:
            return base_decision

        if base_decision == "BLOCK":
            return "BLOCK"
        if tribunal_decision.consensus == "BLOCK":
            return "BLOCK"
        if base_decision == "QUARANTINE":
            return "QUARANTINE"
        if tribunal_decision.consensus == "QUARANTINE":
            return "QUARANTINE"
        if base_decision == "HUMAN_REVIEW":
            return "HUMAN_REVIEW"
        return base_decision

    def _reason(
        self,
        *,
        permission_evaluation: PermissionEvaluation,
        tribunal_decision: TribunalDecision | None,
        tool_result: SandboxToolResult | None,
        final_decision: str,
        side_effect_prevented: str | None,
    ) -> str:
        parts = [permission_evaluation.reason]
        if tribunal_decision is not None:
            parts.append(tribunal_decision.explanation)
        if final_decision == "ALLOW" and tool_result is not None:
            parts.append(tool_result.side_effect_summary)
        elif side_effect_prevented:
            parts.append(side_effect_prevented)
        return " ".join(part.strip() for part in parts if part.strip())

    def _prevented_effect(self, tool_name: str) -> str:
        messages = {
            "email.send_external": "External email delivery was blocked before execution.",
            "finance.export_external": "Finance export was prevented before any external artifact was created.",
            "contracts.rewrite": "Contract rewrite was blocked before any clause changed.",
            "crm.export": "CRM export was blocked before any bulk data left the control plane.",
            "hr.records.export": "HR records export was blocked before any archive was assembled.",
            "refund.execute": "Refund execution was blocked before any financial side effect occurred.",
            "exploit.generate": "Exploit generation was blocked before any code or payload was produced.",
            "exploit.execute": "Exploit execution was blocked before any sandbox action could occur.",
            "auth.bypass_test": "Authentication bypass testing was blocked before any identity control was exercised.",
            "scanner.run": "Scanner execution was held for human review before any scan simulation ran.",
        }
        return messages.get(tool_name, f"{tool_name} was blocked before execution.")

    def _audit_hash(
        self,
        *,
        request_id: str,
        request: ToolCallRequest,
        inspection: WatcherInspection,
        prediction: Prediction,
        permission_evaluation: PermissionEvaluation,
        tribunal_decision: TribunalDecision | None,
        tool_result: SandboxToolResult | None,
        final_decision: str,
    ) -> str:
        canonical = {
            "request_id": request_id,
            "request": request.model_dump(mode="json", by_alias=True),
            "inspection": inspection.model_dump(mode="json", by_alias=True),
            "prediction": prediction.model_dump(mode="json", by_alias=True),
            "permission": permission_evaluation.model_dump(mode="json", by_alias=True),
            "tribunal": tribunal_decision.model_dump(mode="json", by_alias=True)
            if tribunal_decision
            else None,
            "tool_result": tool_result.model_dump(mode="json", by_alias=True)
            if tool_result
            else None,
            "final_decision": final_decision,
            "timestamp": datetime.now(UTC).isoformat(),
        }
        return hashlib.sha256(
            json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
