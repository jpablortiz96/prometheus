from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from prometheus.core.config import Settings
from prometheus.models.domain import (
    AgentRecord,
    DashboardSnapshot,
    EnterpriseMetric,
    EventEvidence,
    EventImpact,
    EventRecord,
    IncidentCommandCenter,
    IntegrationStatus,
    KPISet,
    KnowledgeEdge,
    KnowledgeGraph,
    KnowledgeNode,
    PolicyPackDefinition,
    PolicySignal,
    ReviewQueueItem,
    Scenario,
)
from prometheus.services.lobstertrap_bridge import LobsterTrapBridge


DATA_DIR = Path(__file__).resolve().parent.parent / "data"


def load_agents() -> list[AgentRecord]:
    raw_agents = json.loads((DATA_DIR / "agents.json").read_text(encoding="utf-8"))
    return [AgentRecord.model_validate(item) for item in raw_agents]


def load_scenarios() -> list[Scenario]:
    raw_scenarios = json.loads((DATA_DIR / "scenarios.json").read_text(encoding="utf-8"))
    return [Scenario.model_validate(item) for item in raw_scenarios]


def policy_pack_definitions() -> list[PolicyPackDefinition]:
    return [
        PolicyPackDefinition(
            id="soc2",
            label="SOC2",
            summary="Access discipline, change control, and egress guardrails.",
            threshold_block=0.92,
            threshold_quarantine=0.72,
            decision_labels={
                "allow": "ALLOW",
                "block": "BLOCK ACCESS PATH",
                "quarantine": "QUARANTINE FOR CONTROL REVIEW",
            },
            compliance_labels=["SOC2-ready", "Audit controls", "Change oversight"],
            sponsor_hint="Built on Veea Lobster Trap DPI + Gemini",
        ),
        PolicyPackDefinition(
            id="hipaa",
            label="HIPAA",
            summary="Patient data and privacy breach containment.",
            threshold_block=0.9,
            threshold_quarantine=0.68,
            decision_labels={
                "allow": "ALLOW WITH LOG",
                "block": "BLOCK PHI ACCESS",
                "quarantine": "HOLD FOR PRIVACY REVIEW",
            },
            compliance_labels=["HIPAA policy pack", "PHI safeguards", "Privacy review"],
            sponsor_hint="Veea inspection floor with privacy-first reasoning",
        ),
        PolicyPackDefinition(
            id="finance",
            label="Finance",
            summary="Transaction integrity, exfiltration prevention, and reporting controls.",
            threshold_block=0.88,
            threshold_quarantine=0.64,
            decision_labels={
                "allow": "ALLOW",
                "block": "BLOCK TOOL CALL",
                "quarantine": "FREEZE WORKFLOW",
            },
            compliance_labels=["Finance governance mode", "Data residency", "Reporting integrity"],
            sponsor_hint="Prometheus predicts transaction drift before execution",
        ),
        PolicyPackDefinition(
            id="gdpr",
            label="GDPR",
            summary="Cross-border data transfer and data-subject protection rules.",
            threshold_block=0.9,
            threshold_quarantine=0.7,
            decision_labels={
                "allow": "ALLOW WITH RECORD",
                "block": "BLOCK DATA TRANSFER",
                "quarantine": "ESCALATE FOR GDPR REVIEW",
            },
            compliance_labels=["GDPR controls", "Data transfer review", "Data subject protection"],
            sponsor_hint="Gemini reasoning explains cross-border privacy risk",
        ),
        PolicyPackDefinition(
            id="internal_ai_acceptable_use",
            label="Internal AI Acceptable Use",
            summary="Internal workforce AI tool restrictions and escalation patterns.",
            threshold_block=0.86,
            threshold_quarantine=0.6,
            decision_labels={
                "allow": "ALLOW",
                "block": "REVOKE TOOL ACCESS",
                "quarantine": "MANAGER APPROVAL REQUIRED",
            },
            compliance_labels=["Acceptable use", "Manager review", "Least privilege"],
            sponsor_hint="Enterprise AI acceptable-use controls layered over Lobster Trap",
        ),
    ]


def policy_pack_map() -> dict[str, PolicyPackDefinition]:
    return {item.id: item for item in policy_pack_definitions()}


def decision_label(decision: str, policy_pack: str) -> str:
    config = policy_pack_map()[policy_pack]
    return config.decision_labels[decision.lower()]


def build_initial_events(scenarios: list[Scenario]) -> list[EventRecord]:
    now = datetime.now(UTC)
    seed = [
        (scenarios[1], "BLOCK", 0.94, "critical", ["data_exfiltration", "intent_mismatch"], -160),
        (scenarios[6], "BLOCK", 0.88, "high", ["pii_extraction"], -88),
        (scenarios[3], "QUARANTINE", 0.79, "high", ["intent_mismatch"], -46),
        (scenarios[9], "ALLOW", 0.24, "medium", ["resource_exhaustion"], 8),
    ]
    events: list[EventRecord] = []
    for index, (scenario, decision, divergence, severity, signals, trust_delta) in enumerate(seed):
        timestamp = (now - timedelta(minutes=(index + 1) * 3)).isoformat()
        events.append(
            EventRecord(
                id=f"evt_seed_{index + 1}",
                scenario_id=scenario.id,
                agent_id=scenario.agent_id,
                title=scenario.name,
                declared_intent=scenario.declared_intent,
                detected_intent=scenario.detected_intent,
                observed_action=scenario.observed_action,
                predicted_action=scenario.predicted_action,
                divergence_score=divergence,
                severity=severity,  # type: ignore[arg-type]
                decision=decision,  # type: ignore[arg-type]
                decision_label=decision_label(decision, scenario.policy_pack),
                explanation=scenario.explanation,
                timestamp=timestamp,
                tribunal_consensus=f"{decision} - 3 judges",
                policy_signals=[
                    PolicySignal(
                        id=signal,
                        label=signal.replace("_", " ").title(),
                        severity="critical" if decision == "BLOCK" else "high",
                    )
                    for signal in signals
                ],
                policy_pack=scenario.policy_pack,
                risk_score=scenario.risk_score,
                review_status="pending" if decision != "ALLOW" else "approved",
                model_used="deterministic-demo",
                evidence=EventEvidence(
                    raw_prompt=scenario.user_prompt,
                    dpi_source="simulated",
                    dpi_mode="simulated",
                    dpi_findings=[
                        "Lobster Trap-style metadata extracted declared-vs-detected intent mismatch.",
                        f"Predicted action {scenario.predicted_action} diverged from observed {scenario.observed_action}.",
                    ],
                    detected_pii=["patient records"] if scenario.id == "pii_extraction" else [],
                    credential_patterns=["key", "token"] if scenario.id == "credential_harvesting" else [],
                    target_domains=["evil.com"] if scenario.id == "data_exfiltration" else [],
                    sensitive_paths=["/var/lib/customers"] if scenario.id == "tool_misuse" else [],
                    risky_commands=["rm -rf /var/lib/customers"] if scenario.id == "tool_misuse" else [],
                    matched_policy_rules=signals,
                    divergence_score=divergence,
                    trust_delta=trust_delta,
                    recommended_action="Freeze tool path and escalate to human review"
                    if decision != "ALLOW"
                    else "Allow with watch-level logging",
                    timeline=[
                        "Prompt entered the control plane.",
                        "Watcher generated DPI metadata.",
                        "Prophet compared expected vs observed behavior.",
                        f"Tribunal sealed {decision}.",
                    ],
                    raw_lobstertrap_output=None,
                    fallback_used=True,
                    fallback_reason="Seeded simulated evidence.",
                    lobstertrap_metadata={
                        "_lobstertrap": {
                            "policy_file": "infra/lobstertrap/prometheus_policy.yaml",
                            "matched_rules": signals,
                            "inspected": True,
                            "mode": "simulated",
                        }
                    },
                ),
                impact=EventImpact(
                    business_impact=scenario.business_impact,
                    regulatory_impact=scenario.regulatory_impact,
                    compliance_concern=scenario.compliance_concern,
                    department=scenario.department,
                    mitre_tactic_label=scenario.mitre_tactic_label,
                    blocked_action=scenario.blocked_action,
                    recommended_remediation=scenario.recommended_remediation,
                    audit_summary=scenario.audit_summary,
                    enterprise_value=scenario.enterprise_value,
                ),
                affected_resources=scenario.affected_resources,
            )
        )
    return events


def build_review_queue(events: list[EventRecord]) -> list[ReviewQueueItem]:
    queue: list[ReviewQueueItem] = []
    for event in events:
        if event.decision == "ALLOW":
            continue
        queue.append(
            ReviewQueueItem(
                event_id=event.id,
                incident_id=event.id,
                severity=event.severity,
                agent_id=event.agent_id,
                requested_action=event.decision,
                business_owner=f"{event.impact.department} control owner",
                policy_pack=event.policy_pack,
                status="pending",
            )
        )
    return queue


def build_active_incident(events: list[EventRecord]) -> IncidentCommandCenter | None:
    if not events:
        return None
    event = events[0]
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


def build_knowledge_graph(agents: list[AgentRecord], events: list[EventRecord]) -> KnowledgeGraph:
    nodes: list[KnowledgeNode] = []
    edges: list[KnowledgeEdge] = []

    agent_positions = [(120, 60 + index * 52) for index in range(len(agents))]
    for index, agent in enumerate(agents):
        x, y = agent_positions[index]
        nodes.append(
            KnowledgeNode(
                id=agent.id,
                label=agent.name,
                type="agent",
                x=x,
                y=y,
                emphasis=agent.status in {"blocked", "quarantine"},
                trust_score=agent.trust_score,
                access_level=agent.access_level,
                policy_exposure=agent.policy_exposure,
                related_event_ids=[event.id for event in events if event.agent_id == agent.id][:3],
            )
        )

    tools = [
        ("tool_crm_connector", "CRM Connector", 310, 70),
        ("tool_doc_parser", "Document Parser", 310, 150),
        ("tool_shell_runner", "Shell Runner", 310, 230),
        ("tool_email_gateway", "Email Gateway", 310, 310),
    ]
    data_stores = [
        ("store_customer_vault", "Customer Vault", 500, 60),
        ("store_finance_ledger", "Finance Ledger", 500, 145),
        ("store_hr_records", "HR Records", 500, 230),
        ("store_audit_lake", "Audit Lake", 500, 315),
    ]
    policy_rules = [
        ("policy_exfiltration", "Policy: Exfiltration", 690, 100),
        ("policy_prompt_injection", "Policy: Prompt Injection", 690, 205),
        ("policy_privacy", "Policy: Privacy", 690, 310),
    ]
    incidents = [
        (f"incident_{event.id}", event.title, 860, 80 + index * 95, event)
        for index, event in enumerate(events[:3])
    ]

    for node_id, label, x, y in tools:
        nodes.append(
            KnowledgeNode(
                id=node_id,
                label=label,
                type="tool",
                x=x,
                y=y,
                access_level="service",
                policy_exposure=["tool execution", "data access"],
            )
        )
    for node_id, label, x, y in data_stores:
        nodes.append(
            KnowledgeNode(
                id=node_id,
                label=label,
                type="data_store",
                x=x,
                y=y,
                access_level="restricted",
                policy_exposure=["privacy", "residency"],
            )
        )
    for node_id, label, x, y in policy_rules:
        nodes.append(
            KnowledgeNode(
                id=node_id,
                label=label,
                type="policy_rule",
                x=x,
                y=y,
                access_level="governance",
                policy_exposure=["control plane"],
            )
        )
    for node_id, label, x, y, event in incidents:
        nodes.append(
            KnowledgeNode(
                id=node_id,
                label=label,
                type="incident",
                x=x,
                y=y,
                emphasis=event.decision != "ALLOW",
                related_event_ids=[event.id],
                policy_exposure=event.evidence.matched_policy_rules,
            )
        )

    edges.extend(
        [
            KnowledgeEdge(from_node="agent_a", to="tool_crm_connector", type="tool"),
            KnowledgeEdge(from_node="agent_b", to="tool_doc_parser", type="tool"),
            KnowledgeEdge(from_node="agent_c", to="tool_doc_parser", type="tool"),
            KnowledgeEdge(from_node="agent_d", to="tool_shell_runner", type="tool"),
            KnowledgeEdge(from_node="agent_e", to="tool_email_gateway", type="tool"),
            KnowledgeEdge(from_node="agent_f", to="tool_doc_parser", type="tool"),
            KnowledgeEdge(from_node="agent_security", to="tool_shell_runner", type="tool"),
            KnowledgeEdge(from_node="tool_crm_connector", to="store_customer_vault", type="normal"),
            KnowledgeEdge(from_node="tool_doc_parser", to="store_audit_lake", type="normal"),
            KnowledgeEdge(from_node="tool_shell_runner", to="store_hr_records", type="watch"),
            KnowledgeEdge(from_node="tool_email_gateway", to="store_finance_ledger", type="normal"),
            KnowledgeEdge(from_node="store_customer_vault", to="policy_exfiltration", type="policy"),
            KnowledgeEdge(from_node="store_finance_ledger", to="policy_exfiltration", type="policy"),
            KnowledgeEdge(from_node="store_hr_records", to="policy_privacy", type="policy"),
            KnowledgeEdge(from_node="store_audit_lake", to="policy_prompt_injection", type="policy"),
            KnowledgeEdge(from_node="agent_a", to="incident_evt_seed_1", type="blocked"),
            KnowledgeEdge(from_node="store_finance_ledger", to="incident_evt_seed_1", type="blocked"),
            KnowledgeEdge(from_node="policy_exfiltration", to="incident_evt_seed_1", type="blocked"),
            KnowledgeEdge(from_node="agent_e", to="incident_evt_seed_2", type="blocked"),
            KnowledgeEdge(from_node="store_hr_records", to="incident_evt_seed_2", type="blocked"),
            KnowledgeEdge(from_node="policy_privacy", to="incident_evt_seed_2", type="blocked"),
            KnowledgeEdge(from_node="agent_e", to="incident_evt_seed_3", type="watch"),
            KnowledgeEdge(from_node="tool_email_gateway", to="incident_evt_seed_3", type="watch"),
            KnowledgeEdge(from_node="policy_prompt_injection", to="incident_evt_seed_3", type="watch"),
            KnowledgeEdge(from_node="agent_c", to="incident_evt_seed_4", type="normal"),
            KnowledgeEdge(from_node="tool_doc_parser", to="incident_evt_seed_4", type="normal"),
            KnowledgeEdge(from_node="store_audit_lake", to="incident_evt_seed_4", type="normal"),
        ]
    )

    return KnowledgeGraph(nodes=nodes, edges=edges)


def build_enterprise_metrics(kpis: KPISet) -> list[EnterpriseMetric]:
    return [
        EnterpriseMetric(
            id="avoided_loss",
            label="Estimated avoided loss",
            value="$2.4M",
            trend="Before Prometheus: agent logs are fragmented across tools.",
            emphasis="positive",
        ),
        EnterpriseMetric(
            id="audit_prep_saved",
            label="Audit prep saved",
            value="38 hours",
            trend="After Prometheus: decisions, evidence, and audit trail are unified.",
            emphasis="positive",
        ),
        EnterpriseMetric(
            id="containment",
            label="Mean time to containment",
            value="201ms",
            trend="Tribunal consensus in under 0.3s",
            emphasis="watch",
        ),
        EnterpriseMetric(
            id="blocked_risky_calls",
            label="Blocked risky tool calls",
            value=str(kpis.attacks_blocked),
            trend="47 blocked before execution",
            emphasis="critical",
        ),
        EnterpriseMetric(
            id="audit_readiness",
            label="Regulator readiness score",
            value="94/100",
            trend="Regulator report available on demand",
            emphasis="positive",
        ),
        EnterpriseMetric(
            id="ciso_confidence",
            label="CISO approval confidence",
            value="91%",
            trend="Executive sign-off for controlled agent rollout",
            emphasis="neutral",
        ),
    ]


def build_seed_snapshot(settings: Settings) -> DashboardSnapshot:
    agents = load_agents()
    scenarios = load_scenarios()
    events = build_initial_events(scenarios)
    kpis = KPISet(
        attacks_blocked=47,
        quarantined=5,
        active_agents=len(agents),
        average_latency_ms=187,
        trust_floor=min(agent.trust_score for agent in agents),
        incidents_24h=58,
    )
    active_policy_pack = "finance"
    bridge = LobsterTrapBridge(settings)
    integration_status = bridge.status(
        gemini_configured=bool(settings.gemini_api_key),
        gemini_available=False,
        gemini_last_error=None,
        active_policy_pack=active_policy_pack,
        database_available=False,
    )
    return DashboardSnapshot(
        agents=agents,
        events=events,
        kpis=kpis,
        knowledge_graph=build_knowledge_graph(agents, events),
        active_tribunal=None,
        active_incident=build_active_incident(events),
        review_queue=build_review_queue(events),
        policy_packs=policy_pack_definitions(),
        integration_status=integration_status,
        enterprise_metrics=build_enterprise_metrics(kpis),
        product_version=settings.app_version,
        tenant_label=settings.tenant_label,
        compliance_labels=["SOC2-ready", "HIPAA policy pack", "Finance governance mode"],
        status_message="All guardians synchronized. Deterministic demo mode is armed.",
        sponsor_status=settings.sponsor_status,
        active_policy_pack=active_policy_pack,
        demo_running=False,
        demo_mode=False,
        countdown_seconds=0,
        demo_stage="Normal operations",
        demo_progress_percent=0,
        report_ready=False,
        connection_mode="fallback" if not settings.gemini_api_key else "live",
        last_updated=datetime.now(UTC).isoformat(),
    )
