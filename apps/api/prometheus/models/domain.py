from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


def to_camel(value: str) -> str:
    head, *tail = value.split("_")
    return head + "".join(part.capitalize() for part in tail)


class PrometheusModel(BaseModel):
    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        use_enum_values=True,
    )


class HealthResponse(PrometheusModel):
    status: str
    mode: Literal["live-gemini", "deterministic-demo"]
    version: str
    timestamp: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())


class PolicySignal(PrometheusModel):
    id: str
    label: str
    severity: Literal["low", "medium", "high", "critical"]


class PolicyPackDefinition(PrometheusModel):
    id: str
    label: str
    summary: str
    threshold_block: float
    threshold_quarantine: float
    decision_labels: dict[str, str]
    compliance_labels: list[str]
    sponsor_hint: str


class EnterpriseMetric(PrometheusModel):
    id: str
    label: str
    value: str
    trend: str
    emphasis: Literal["positive", "watch", "critical", "neutral"]


class IntegrationStatus(PrometheusModel):
    gemini_configured: bool = False
    gemini_connected: bool = False
    gemini_available: bool = False
    gemini_mode: Literal["connected", "simulated"] = "simulated"
    gemini_reasoning_model: str = "gemini-3.1-pro-preview"
    gemini_fast_model: str = "gemini-3-flash-preview"
    gemini_lite_model: str = "gemini-3.1-flash-lite-preview"
    gemini_last_error: str | None = None
    lobster_trap_enabled: bool = False
    lobster_trap_available: bool = False
    lobster_trap_bin_found: bool = False
    lobster_trap_mode: Literal["simulated", "live_cli", "configured_but_unavailable"] = "simulated"
    lobster_trap_bin_path: str = ""
    lobster_trap_policy_path: str = ""
    lobster_trap_last_error: str | None = None
    policy_file_found: bool = False
    policy_rule_count: int = 0
    policy_rules_count: int = 0
    demo_fallback_active: bool
    audit_trail_online: bool
    database_available: bool
    active_policy_pack: str
    models: dict[str, str] = Field(default_factory=dict)


class AgentRecord(PrometheusModel):
    id: str
    name: str
    role: str
    model: str
    baseline: str
    status: Literal["normal", "watching", "blocked", "quarantine"]
    trust_score: int
    trust_delta: int
    last_action: str
    last_event_at: str
    predicted_action: str
    divergence_score: float
    policy_pack: str
    sparkline: list[int]
    model_source: Literal["gemini", "deterministic"]
    access_level: str
    policy_exposure: list[str]


class KPISet(PrometheusModel):
    attacks_blocked: int
    quarantined: int
    active_agents: int
    average_latency_ms: int
    trust_floor: int
    incidents_24h: int


class JudgeVote(PrometheusModel):
    judge: str
    role: str
    vote: Literal["ALLOW", "BLOCK", "QUARANTINE"]
    reasoning: str
    model_used: str


class TribunalDecision(PrometheusModel):
    scenario_id: str
    agent_id: str
    consensus: Literal["ALLOW", "BLOCK", "QUARANTINE"]
    latency_ms: int
    explanation: str
    model_used: str
    judges: list[JudgeVote]


class Prediction(PrometheusModel):
    predicted_action: str
    divergence_score: float
    confidence: float
    explanation: str
    model_used: str


class NormalizedDPIResult(PrometheusModel):
    source: Literal["veea_lobstertrap_cli", "simulated"] = "simulated"
    mode: Literal["live_cli", "live_cli_error", "simulated"] = "simulated"
    verdict: str = "ALLOW"
    action: Literal["ALLOW", "BLOCK", "QUARANTINE"] = "ALLOW"
    risk_score: float = 0.0
    matched_rules: list[str] = Field(default_factory=list)
    detected_intent: str = "general"
    contains_pii: bool = False
    contains_credentials: bool = False
    contains_injection_patterns: bool = False
    contains_system_commands: bool = False
    contains_urls: bool = False
    target_domains: list[str] = Field(default_factory=list)
    sensitive_paths: list[str] = Field(default_factory=list)
    raw_lobstertrap_output: str | None = None
    fallback_used: bool = False
    fallback_reason: str | None = None


class WatcherInspection(PrometheusModel):
    declared_intent: str
    detected_intent: str
    risk_score: float
    floor_decision: Literal["ALLOW", "BLOCK", "QUARANTINE"]
    dpi_source: Literal["veea_lobstertrap_cli", "simulated"] = "simulated"
    dpi_mode: Literal["live_cli", "live_cli_error", "simulated"] = "simulated"
    policy_signals: list[PolicySignal]
    metadata: dict[str, Any]
    dpi_findings: list[str]
    detected_pii: list[str]
    credential_patterns: list[str]
    target_domains: list[str]
    sensitive_paths: list[str] = Field(default_factory=list)
    risky_commands: list[str]
    matched_policy_rules: list[str]
    raw_lobstertrap_output: str | None = None
    fallback_used: bool = False
    fallback_reason: str | None = None
    recommended_action: str


class EventEvidence(PrometheusModel):
    raw_prompt: str
    dpi_source: Literal["veea_lobstertrap_cli", "simulated"] = "simulated"
    dpi_mode: Literal["live_cli", "live_cli_error", "simulated"] = "simulated"
    dpi_findings: list[str]
    detected_pii: list[str]
    credential_patterns: list[str]
    target_domains: list[str]
    sensitive_paths: list[str] = Field(default_factory=list)
    risky_commands: list[str]
    matched_policy_rules: list[str]
    divergence_score: float
    trust_delta: int
    recommended_action: str
    timeline: list[str]
    raw_lobstertrap_output: str | None = None
    fallback_used: bool = False
    fallback_reason: str | None = None
    lobstertrap_metadata: dict[str, Any]


class EventImpact(PrometheusModel):
    business_impact: str
    regulatory_impact: str
    compliance_concern: str
    department: str
    mitre_tactic_label: str
    blocked_action: str
    recommended_remediation: str
    audit_summary: str
    enterprise_value: str


class EventRecord(PrometheusModel):
    id: str
    scenario_id: str
    agent_id: str
    title: str
    declared_intent: str
    detected_intent: str
    observed_action: str
    predicted_action: str
    divergence_score: float
    severity: Literal["low", "medium", "high", "critical"]
    decision: Literal["ALLOW", "BLOCK", "QUARANTINE"]
    decision_label: str
    explanation: str
    timestamp: str
    tribunal_consensus: str
    policy_signals: list[PolicySignal]
    policy_pack: str
    risk_score: float
    review_status: Literal["pending", "approved", "denied", "quarantined", "escalated"]
    model_used: str
    evidence: EventEvidence
    impact: EventImpact
    affected_resources: list[str]


class IncidentCommandCenter(PrometheusModel):
    incident_id: str
    severity: Literal["low", "medium", "high", "critical"]
    affected_agent: str
    declared_intent: str
    detected_intent: str
    predicted_action: str
    observed_action: str
    policy_matched: list[str]
    final_decision: Literal["ALLOW", "BLOCK", "QUARANTINE"]
    decision_label: str
    business_impact: str
    regulatory_impact: str
    department: str
    compliance_concern: str
    risk_score: float
    trust_delta: int


class ReviewQueueItem(PrometheusModel):
    event_id: str
    incident_id: str
    severity: Literal["low", "medium", "high", "critical"]
    agent_id: str
    requested_action: Literal["ALLOW", "BLOCK", "QUARANTINE"]
    business_owner: str
    policy_pack: str
    status: Literal["pending", "approved", "denied", "quarantined", "escalated"]


class KnowledgeNode(PrometheusModel):
    id: str
    label: str
    type: Literal["agent", "tool", "data_store", "policy_rule", "incident"]
    x: float
    y: float
    emphasis: bool = False
    trust_score: int | None = None
    access_level: str | None = None
    policy_exposure: list[str] | None = None
    related_event_ids: list[str] | None = None


class KnowledgeEdge(PrometheusModel):
    from_node: str = Field(alias="from")
    to: str
    type: Literal["normal", "blocked", "watch", "tool", "policy"]


class KnowledgeGraph(PrometheusModel):
    nodes: list[KnowledgeNode]
    edges: list[KnowledgeEdge]


class DashboardSnapshot(PrometheusModel):
    agents: list[AgentRecord]
    events: list[EventRecord]
    kpis: KPISet
    knowledge_graph: KnowledgeGraph
    active_tribunal: TribunalDecision | None
    active_incident: IncidentCommandCenter | None
    review_queue: list[ReviewQueueItem]
    policy_packs: list[PolicyPackDefinition]
    integration_status: IntegrationStatus
    enterprise_metrics: list[EnterpriseMetric]
    product_version: str
    tenant_label: str
    compliance_labels: list[str]
    status_message: str
    sponsor_status: str
    active_policy_pack: str
    demo_running: bool
    demo_mode: bool
    countdown_seconds: int
    demo_stage: str
    demo_progress_percent: int
    report_ready: bool
    last_tool_call: ToolCallDecision | None = None
    recent_tool_calls: list[ToolCallDecision] = Field(default_factory=list)
    permission_matrix: GatewayPermissionMatrix = Field(
        default_factory=lambda: GatewayPermissionMatrix(tools=[], rows=[])
    )
    connection_mode: Literal["live", "fallback"]
    last_updated: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())


class Scenario(PrometheusModel):
    id: str
    name: str
    user_prompt: str
    declared_intent: str
    detected_intent: str
    expected_decision: Literal["ALLOW", "BLOCK", "QUARANTINE"]
    risk_score: float
    policy_pack: str
    explanation: str
    agent_id: str
    observed_action: str
    predicted_action: str
    mitre_tactic_label: str
    department: str
    business_impact: str
    regulatory_impact: str
    compliance_concern: str
    blocked_action: str
    recommended_remediation: str
    audit_summary: str
    enterprise_value: str
    affected_resources: list[str]


class RedTeamRunRequest(PrometheusModel):
    mode: Literal["drill", "demo"] = "drill"


class RedTeamRunResponse(PrometheusModel):
    started: bool
    mode: Literal["drill", "demo"]
    message: str


class TribunalEvaluateRequest(PrometheusModel):
    agent_id: str
    scenario_id: str
    user_prompt: str
    declared_intent: str
    detected_intent: str
    expected_decision: Literal["ALLOW", "BLOCK", "QUARANTINE"]
    risk_score: float
    policy_pack: str
    observed_action: str


class AuditReportRequest(PrometheusModel):
    scenario_id: str | None = None
    incident_id: str | None = None


class AuditReportResponse(PrometheusModel):
    title: str
    summary: str
    timeline: list[str]
    markdown: str
    html: str
    evidence_table: list[dict[str, str]]
    model_used: str
    generated_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())


class AuditReportExport(PrometheusModel):
    title: str
    format: Literal["html", "markdown"]
    content: str
    file_name: str
    generated_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    model_used: str


class AuditBundleResponse(PrometheusModel):
    incident_id: str
    generated_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    tenant: str
    policy_pack: str
    decision: str
    risk_score: float
    evidence: EventEvidence
    timeline: list[str]
    tribunal_votes: list[JudgeVote]
    remediation: str
    markdown_report: str
    html_report: str
    audit_hash: str
    tamper_notice: str


class AuditReportArchiveItem(PrometheusModel):
    incident_id: str
    title: str
    generated_at: str
    format: Literal["bundle", "html", "markdown"]
    decision: str
    policy_pack: str
    audit_hash: str
    model_used: str


class IncidentSummary(PrometheusModel):
    incident_id: str
    title: str
    agent_id: str
    severity: Literal["low", "medium", "high", "critical"]
    decision: Literal["ALLOW", "BLOCK", "QUARANTINE"]
    decision_label: str
    policy_pack: str
    risk_score: float
    timestamp: str


class IncidentDetailResponse(PrometheusModel):
    incident: IncidentCommandCenter
    event: EventRecord
    reports: list[AuditReportArchiveItem]


class PolicyPackSelectRequest(PrometheusModel):
    policy_pack_id: str


class PolicyPackSelectResponse(PrometheusModel):
    active_policy_pack: str


class ReviewQueueActionRequest(PrometheusModel):
    event_id: str
    action: Literal["pending", "approved", "denied", "quarantined", "escalated"]


class ReviewQueueActionResponse(PrometheusModel):
    event_id: str
    status: Literal["pending", "approved", "denied", "quarantined", "escalated"]
    message: str


class ScenarioRunRequest(PrometheusModel):
    scenario_id: str


class SandboxToolResult(PrometheusModel):
    tool_name: str
    executed: bool
    result: dict[str, Any] = Field(default_factory=dict)
    side_effect_summary: str
    data_classification: str


class PermissionEvaluation(PrometheusModel):
    agent_id: str
    tool_name: str
    policy_pack: str
    permission_state: Literal["allowed", "denied", "human_review", "quarantine"]
    allowed: bool
    requires_human_review: bool = False
    external_egress: bool = False
    data_classification: str = "internal"
    reason: str
    matched_restrictions: list[str] = Field(default_factory=list)


class ToolCallRequest(PrometheusModel):
    agent_id: str
    tool_name: str
    declared_intent: str
    prompt: str
    payload: dict[str, Any] = Field(default_factory=dict)
    policy_pack: str
    requires_human_review: bool = False


class ToolCallDecision(PrometheusModel):
    request_id: str
    agent_id: str
    tool_name: str
    declared_intent: str
    detected_intent: str
    predicted_action: str
    observed_action: str
    dpi_source: Literal["veea_lobstertrap_cli", "simulated"] = "simulated"
    dpi_mode: Literal["live_cli", "live_cli_error", "simulated"] = "simulated"
    decision: Literal["ALLOW", "BLOCK", "QUARANTINE", "HUMAN_REVIEW"]
    tool_executed: bool
    risk_score: float
    matched_rules: list[str] = Field(default_factory=list)
    reason: str
    raw_lobstertrap_output: str | None = None
    raw_lobstertrap_output_preview: str | None = None
    evidence_preview: str | None = None
    tribunal_votes: list[JudgeVote] = Field(default_factory=list)
    audit_hash: str
    created_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    permission_evaluation: PermissionEvaluation
    tool_result: SandboxToolResult | None = None
    side_effect_prevented: str | None = None
    side_effect_prevented_flag: bool = False
    source_event_id: str | None = None


class PermissionMatrixRow(PrometheusModel):
    agent_id: str
    agent_name: str
    cells: dict[str, Literal["allowed", "denied", "human_review", "quarantine"]] = Field(
        default_factory=dict
    )


class GatewayPermissionMatrix(PrometheusModel):
    tools: list[str] = Field(default_factory=list)
    rows: list[PermissionMatrixRow] = Field(default_factory=list)


class DocumentInspectRequest(PrometheusModel):
    document_name: str
    document_content: str
    agent_id: str
    declared_intent: str
    tool_name: str
    policy_pack: str
    requires_human_review: bool = False


class DocumentInspectResponse(PrometheusModel):
    document_name: str
    content_excerpt: str
    document_content_preview: str | None = None
    evidence_preview: str | None = None
    tool_decision: ToolCallDecision
    incident_id: str | None = None
    audit_hash: str


class LobsterTrapDebugResponse(PrometheusModel):
    enabled: bool
    available: bool
    mode: str
    bin_path: str
    bin_exists: bool
    bin_is_file: bool
    policy_path: str
    policy_exists: bool
    policy_rules_count: int
    version_returncode: int | None = None
    version_stdout_preview: str | None = None
    version_stderr_preview: str | None = None
    version_elapsed_ms: int | None = None
    inspect_test_returncode: int | None = None
    inspect_test_stdout_preview: str | None = None
    inspect_test_stderr_preview: str | None = None
    inspect_test_elapsed_ms: int | None = None
    last_error: str | None = None


class PolicyPatchRecommendation(PrometheusModel):
    rule_name: str
    condition: str
    action: str
    reason: str


class PermissionChangeRecommendation(PrometheusModel):
    agent_id: str
    tool_name: str
    recommended_state: Literal["allowed", "denied", "human_review", "quarantine"]
    reason: str


class ThreatIntelScenarioDraft(PrometheusModel):
    name: str
    declared_intent: str
    detected_intent: str
    attempted_tool: str
    prompt: str
    expected_decision: Literal["ALLOW", "BLOCK", "QUARANTINE", "HUMAN_REVIEW"]
    safety_note: str


class ThreatIntelInput(PrometheusModel):
    title: str
    source: str
    report_text: str
    policy_pack: str
    industry: str
    create_scenario: bool = True
    run_simulation: bool = True


class ThreatIntelExtraction(PrometheusModel):
    threat_summary: str
    attacker_goal: str
    ai_misuse_pattern: str
    suspected_tactics: list[str] = Field(default_factory=list)
    affected_enterprise_functions: list[str] = Field(default_factory=list)
    risky_agent_behaviors: list[str] = Field(default_factory=list)
    dangerous_tool_calls: list[str] = Field(default_factory=list)
    recommended_policy_rules: list[PolicyPatchRecommendation] = Field(default_factory=list)
    recommended_permission_changes: list[PermissionChangeRecommendation] = Field(default_factory=list)
    safe_scenario: ThreatIntelScenarioDraft


class ThreatIntelAuditRecord(PrometheusModel):
    incident_id: str
    decision: str
    policy_pack: str
    audit_hash: str
    generated_at: str


class ThreatIntelRunResult(PrometheusModel):
    run_id: str
    title: str
    source: str
    policy_pack: str
    industry: str
    extraction: ThreatIntelExtraction
    generated_scenario: ThreatIntelScenarioDraft | None = None
    policy_patch: list[PolicyPatchRecommendation] = Field(default_factory=list)
    gateway_decision: ToolCallDecision | None = None
    audit_bundle: ThreatIntelAuditRecord | None = None
    blocked_before_execution: bool | None = None
    created_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())


class ThreatIntelRunSummary(PrometheusModel):
    run_id: str
    title: str
    source: str
    policy_pack: str
    industry: str
    decision: str | None = None
    attempted_tool: str | None = None
    tool_executed: bool | None = None
    incident_id: str | None = None
    blocked_before_execution: bool | None = None
    created_at: str


class LobsterTrapInspectRequest(PrometheusModel):
    prompt: str
    declared_intent: str
    agent_id: str
    policy_pack: str = "finance"
    detected_intent: str | None = None


class LobsterTrapInspectResponse(PrometheusModel):
    agent_id: str
    inspection: WatcherInspection
    status_label: str
    policy_rule_count: int
    policy_rules_count: int = 0


class StructuredPrediction(PrometheusModel):
    predicted_action: str
    divergence_score: float
    confidence: float
    explanation: str


class StructuredJudgeVote(PrometheusModel):
    judge: str
    role: str
    vote: Literal["ALLOW", "BLOCK", "QUARANTINE"]
    reasoning: str


class StructuredTribunal(PrometheusModel):
    consensus: Literal["ALLOW", "BLOCK", "QUARANTINE"]
    explanation: str
    judges: list[StructuredJudgeVote]


class StructuredAuditNarrative(PrometheusModel):
    title: str
    summary: str
    timeline: list[str]
    markdown: str
    html: str
    evidence_table: list[dict[str, str]]
