from __future__ import annotations

from datetime import UTC, datetime

from prometheus.models.domain import (
    AgentRecord,
    AuditReportResponse,
    EventEvidence,
    EventImpact,
    EventRecord,
    IncidentCommandCenter,
    Prediction,
    Scenario,
    StructuredAuditNarrative,
    TribunalDecision,
    WatcherInspection,
)
from prometheus.services.gemini_router import GeminiRouter


class HistorianService:
    def __init__(self, router: GeminiRouter) -> None:
        self.router = router

    async def build_report(
        self,
        *,
        agent: AgentRecord,
        scenario: Scenario,
        event: EventRecord,
        decision: TribunalDecision,
        inspection: WatcherInspection,
    ) -> AuditReportResponse:
        fallback = self._fallback(agent, scenario, event, decision, inspection)

        prompt = f"""
Return strict JSON with keys title, summary, timeline, markdown, html, evidence_table.
System: PROMETHEUS Historian.
Agent: {agent.name} ({agent.id})
Scenario: {scenario.name}
Decision: {decision.consensus}
Explanation: {decision.explanation}
Watcher metadata: {inspection.metadata}
Business impact: {scenario.business_impact}
Regulatory impact: {scenario.regulatory_impact}
Remediation: {scenario.recommended_remediation}
Sponsor visibility: Veea Lobster Trap DPI + Gemini model routing
"""

        payload, model_used = await self.router.generate_structured(
            task="reasoning",
            prompt=prompt,
            schema=StructuredAuditNarrative,
            fallback=lambda: fallback,
        )

        return AuditReportResponse(
            title=payload.title,
            summary=payload.summary,
            timeline=payload.timeline,
            markdown=payload.markdown,
            html=payload.html,
            evidence_table=payload.evidence_table,
            model_used=model_used,
        )

    def build_event(
        self,
        *,
        scenario: Scenario,
        prediction: Prediction,
        decision: TribunalDecision,
        inspection: WatcherInspection,
        trust_delta: int,
    ) -> EventRecord:
        severity = "critical" if scenario.risk_score >= 0.9 else "high"
        if decision.consensus == "QUARANTINE":
            severity = "high"
        elif decision.consensus == "ALLOW":
            severity = "medium"

        explanation = (
            f"Watcher matched {len(inspection.policy_signals)} policy signals. "
            f"Prophet expected {prediction.predicted_action}; observed {scenario.observed_action}. "
            f"Tribunal decision: {decision.consensus}."
        )

        evidence = EventEvidence(
            raw_prompt=scenario.user_prompt,
            dpi_source=inspection.dpi_source,
            dpi_mode=inspection.dpi_mode,
            dpi_findings=inspection.dpi_findings,
            detected_pii=inspection.detected_pii,
            credential_patterns=inspection.credential_patterns,
            target_domains=inspection.target_domains,
            sensitive_paths=inspection.sensitive_paths,
            risky_commands=inspection.risky_commands,
            matched_policy_rules=inspection.matched_policy_rules,
            divergence_score=prediction.divergence_score,
            trust_delta=trust_delta,
            recommended_action=inspection.recommended_action,
            timeline=[
                (
                    "Veea Lobster Trap CLI inspected the prompt and policy floor."
                    if inspection.dpi_source == "veea_lobstertrap_cli"
                    else "Deterministic fallback inspection ran because the Lobster Trap CLI was unavailable."
                ),
                "Watcher inspected raw prompt and declared intent.",
                f"Prophet predicted {prediction.predicted_action}.",
                f"Tribunal sealed {decision.consensus}.",
            ],
            raw_lobstertrap_output=inspection.raw_lobstertrap_output,
            fallback_used=inspection.fallback_used,
            fallback_reason=inspection.fallback_reason,
            lobstertrap_metadata=inspection.metadata,
        )

        impact = EventImpact(
            business_impact=scenario.business_impact,
            regulatory_impact=scenario.regulatory_impact,
            compliance_concern=scenario.compliance_concern,
            department=scenario.department,
            mitre_tactic_label=scenario.mitre_tactic_label,
            blocked_action=scenario.blocked_action,
            recommended_remediation=scenario.recommended_remediation,
            audit_summary=scenario.audit_summary,
            enterprise_value=scenario.enterprise_value,
        )

        return EventRecord(
            id=f"evt_{scenario.id}_{int(datetime.now(UTC).timestamp())}",
            scenario_id=scenario.id,
            agent_id=scenario.agent_id,
            title=scenario.name,
            declared_intent=scenario.declared_intent,
            detected_intent=scenario.detected_intent,
            observed_action=scenario.observed_action,
            predicted_action=prediction.predicted_action,
            divergence_score=prediction.divergence_score,
            severity=severity,  # type: ignore[arg-type]
            decision=decision.consensus,
            decision_label=decision.consensus,
            explanation=explanation,
            timestamp=datetime.now(UTC).isoformat(),
            tribunal_consensus=f"{decision.consensus} - {len(decision.judges)} judges",
            policy_signals=inspection.policy_signals,
            policy_pack=scenario.policy_pack,
            risk_score=scenario.risk_score,
            review_status="pending" if decision.consensus != "ALLOW" else "approved",
            model_used=decision.model_used,
            evidence=evidence,
            impact=impact,
            affected_resources=scenario.affected_resources,
        )

    def build_incident(self, event: EventRecord) -> IncidentCommandCenter:
        return IncidentCommandCenter(
            incident_id=event.id,
            severity=event.severity,
            affected_agent=event.agent_id,
            declared_intent=event.declared_intent,
            detected_intent=event.detected_intent,
            predicted_action=event.predicted_action,
            observed_action=event.observed_action,
            policy_matched=event.evidence.matched_policy_rules,
            final_decision=event.decision,
            decision_label=event.decision_label,
            business_impact=event.impact.business_impact,
            regulatory_impact=event.impact.regulatory_impact,
            department=event.impact.department,
            compliance_concern=event.impact.compliance_concern,
            risk_score=event.risk_score,
            trust_delta=event.evidence.trust_delta,
        )

    def _fallback(
        self,
        agent: AgentRecord,
        scenario: Scenario,
        event: EventRecord,
        decision: TribunalDecision,
        inspection: WatcherInspection,
    ) -> StructuredAuditNarrative:
        timeline = [
            f"{event.timestamp}: Watcher inspected prompt and matched {len(inspection.policy_signals)} policy signals.",
            f"{event.timestamp}: Prophet predicted {event.predicted_action} but observed {event.observed_action}.",
            f"{event.timestamp}: Tribunal consensus {decision.consensus} in {decision.latency_ms}ms.",
            f"{event.timestamp}: Historian preserved Veea Lobster Trap DPI and Gemini routing metadata.",
        ]
        evidence_table = [
            {"label": "Declared intent", "value": scenario.declared_intent},
            {"label": "Detected intent", "value": scenario.detected_intent},
            {"label": "Policy matched", "value": ", ".join(inspection.matched_policy_rules) or "none"},
            {"label": "Risk score", "value": f"{scenario.risk_score:.2f}"},
            {"label": "Decision rationale", "value": decision.explanation},
            {"label": "Recommended remediation", "value": scenario.recommended_remediation},
        ]
        markdown = "\n".join(
            [
                f"# {scenario.name}",
                "",
                "## Executive Summary",
                (
                    f"{agent.name} triggered {scenario.detected_intent}. Prometheus issued "
                    f"**{decision.consensus}** using Veea Lobster Trap DPI floor signals and Gemini model routing."
                ),
                "",
                "## Incident Timeline",
                *[f"- {item}" for item in timeline],
                "",
                "## Evidence Table",
                *[f"- {row['label']}: {row['value']}" for row in evidence_table],
                "",
                "## Tribunal Vote",
                *[f"- {vote.judge}: {vote.vote} - {vote.reasoning}" for vote in decision.judges],
                "",
                "## Recommended Remediation",
                f"- {scenario.recommended_remediation}",
            ]
        )
        html_rows = "".join(
            [
                f"<tr><th>{row['label']}</th><td>{row['value']}</td></tr>"
                for row in evidence_table
            ]
        )
        html = (
            "<html><body style='font-family:Arial,sans-serif;background:#faf8f2;color:#0a0a0b;padding:32px;'>"
            f"<h1>{scenario.name}</h1>"
            "<h2>Executive Summary</h2>"
            f"<p>{agent.name} triggered {scenario.detected_intent}. Prometheus issued <strong>{decision.consensus}</strong> "
            "using Veea Lobster Trap DPI floor signals and Gemini model routing.</p>"
            "<h2>Incident Timeline</h2><ul>"
            + "".join([f"<li>{item}</li>" for item in timeline])
            + "</ul><h2>Evidence Table</h2><table border='1' cellspacing='0' cellpadding='8'>"
            + html_rows
            + "</table><h2>Recommended Remediation</h2>"
            f"<p>{scenario.recommended_remediation}</p></body></html>"
        )

        return StructuredAuditNarrative(
            title=f"{scenario.name} - Audit Narrative",
            summary=(
                f"{agent.name} triggered {scenario.detected_intent}. "
                f"Prometheus rendered a {decision.consensus} decision using behavioral divergence and policy floor evidence."
            ),
            timeline=timeline,
            markdown=markdown,
            html=html,
            evidence_table=evidence_table,
        )
