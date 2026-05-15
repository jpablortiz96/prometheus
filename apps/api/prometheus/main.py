from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse, StreamingResponse

from prometheus import __version__
from prometheus.core.config import get_settings
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
    HealthResponse,
    IncidentDetailResponse,
    IncidentSummary,
    IntegrationStatus,
    LobsterTrapDebugResponse,
    KPISet,
    LobsterTrapInspectRequest,
    LobsterTrapInspectResponse,
    PolicyPackSelectRequest,
    PolicyPackSelectResponse,
    RedTeamRunRequest,
    RedTeamRunResponse,
    ReviewQueueActionRequest,
    ReviewQueueActionResponse,
    Scenario,
    ScenarioRunRequest,
    ThreatIntelInput,
    ThreatIntelRunResult,
    ThreatIntelRunSummary,
    ToolCallDecision,
    ToolCallRequest,
    TribunalDecision,
    TribunalEvaluateRequest,
)
from prometheus.services.runtime import PrometheusRuntime


RAW_PREVIEW_LIMIT = 1500
TEXT_PREVIEW_LIMIT = 320


def _truncate_text(value: str | None, limit: int) -> str | None:
    if value is None:
        return None
    normalized = value.strip()
    if len(normalized) <= limit:
        return normalized
    return f"{normalized[:limit].rstrip()}... [truncated]"


def _build_evidence_preview(decision: ToolCallDecision) -> str:
    fragments = [
        f"Decision {decision.decision}",
        f"risk {decision.risk_score:.2f}",
        f"rules {len(decision.matched_rules)}",
    ]
    if decision.side_effect_prevented:
        fragments.append(decision.side_effect_prevented)
    elif decision.tool_result is not None:
        fragments.append(decision.tool_result.side_effect_summary)
    return " | ".join(fragments)


def _compact_tool_call_response(
    decision: ToolCallDecision,
    *,
    include_raw: bool,
) -> ToolCallDecision:
    raw_preview = _truncate_text(decision.raw_lobstertrap_output, RAW_PREVIEW_LIMIT)
    return decision.model_copy(
        update={
            "raw_lobstertrap_output": decision.raw_lobstertrap_output if include_raw else raw_preview,
            "raw_lobstertrap_output_preview": raw_preview,
            "evidence_preview": _build_evidence_preview(decision),
        }
    )


def _compact_document_response(
    response: DocumentInspectResponse,
    *,
    include_raw: bool,
) -> DocumentInspectResponse:
    compact_decision = _compact_tool_call_response(
        response.tool_decision,
        include_raw=include_raw,
    )
    return response.model_copy(
        update={
            "tool_decision": compact_decision,
            "document_content_preview": response.document_content_preview
            or response.content_excerpt[:TEXT_PREVIEW_LIMIT],
            "evidence_preview": response.evidence_preview or compact_decision.evidence_preview,
        }
    )


def _compact_threat_intel_response(
    response: ThreatIntelRunResult,
    *,
    include_raw: bool,
) -> ThreatIntelRunResult:
    if response.gateway_decision is None:
        return response
    return response.model_copy(
        update={
            "gateway_decision": _compact_tool_call_response(
                response.gateway_decision,
                include_raw=include_raw,
            )
        }
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    runtime = PrometheusRuntime(settings)
    await runtime.initialize()
    app.state.runtime = runtime
    yield


app = FastAPI(
    title="PROMETHEUS API",
    version=__version__,
    lifespan=lifespan,
    docs_url="/docs",
    openapi_url="/openapi.json",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=get_settings().resolved_cors_allowed_origins(),
    allow_origin_regex=get_settings().resolved_cors_allowed_origin_regex(),
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "Accept"],
)


def get_runtime() -> PrometheusRuntime:
    return app.state.runtime


@app.get("/api/docs", include_in_schema=False)
async def legacy_docs_redirect() -> RedirectResponse:
    return RedirectResponse(url="/docs")


@app.get("/api/openapi.json", include_in_schema=False)
async def legacy_openapi_redirect() -> RedirectResponse:
    return RedirectResponse(url="/openapi.json")


@app.get("/health", response_model=HealthResponse)
async def health(
    runtime: PrometheusRuntime = Depends(get_runtime),
) -> HealthResponse:
    return HealthResponse(
        status="ok",
        mode="live-gemini" if runtime.router.available else "deterministic-demo",
        version=__version__,
    )


@app.get("/api/snapshot", response_model=DashboardSnapshot)
async def dashboard_snapshot(
    runtime: PrometheusRuntime = Depends(get_runtime),
) -> DashboardSnapshot:
    return await runtime.snapshot()


@app.get("/api/agents", response_model=list[AgentRecord])
async def agents(runtime: PrometheusRuntime = Depends(get_runtime)) -> list[AgentRecord]:
    return (await runtime.snapshot()).agents


@app.get("/api/events", response_model=list[EventRecord])
async def events(runtime: PrometheusRuntime = Depends(get_runtime)) -> list[EventRecord]:
    return (await runtime.snapshot()).events


@app.get("/api/kpis", response_model=KPISet)
async def kpis(runtime: PrometheusRuntime = Depends(get_runtime)) -> KPISet:
    return (await runtime.snapshot()).kpis


@app.get("/api/integrations/status", response_model=IntegrationStatus)
async def integrations_status(
    runtime: PrometheusRuntime = Depends(get_runtime),
) -> IntegrationStatus:
    return await runtime.integrations_status()


@app.get("/api/incidents", response_model=list[IncidentSummary])
async def incidents(
    runtime: PrometheusRuntime = Depends(get_runtime),
) -> list[IncidentSummary]:
    return await runtime.list_incidents()


@app.get("/api/incidents/{incident_id}", response_model=IncidentDetailResponse)
async def incident_detail(
    incident_id: str,
    runtime: PrometheusRuntime = Depends(get_runtime),
) -> IncidentDetailResponse:
    return await runtime.incident_detail(incident_id)


@app.get("/api/audit/reports", response_model=list[AuditReportArchiveItem])
async def audit_reports(
    runtime: PrometheusRuntime = Depends(get_runtime),
) -> list[AuditReportArchiveItem]:
    return await runtime.list_reports()


@app.get("/api/scenarios", response_model=list[Scenario])
async def scenarios(
    runtime: PrometheusRuntime = Depends(get_runtime),
) -> list[Scenario]:
    return await runtime.list_scenarios()


@app.post("/api/red-team/run", response_model=RedTeamRunResponse)
async def red_team_run(
    request: RedTeamRunRequest,
    runtime: PrometheusRuntime = Depends(get_runtime),
) -> RedTeamRunResponse:
    return await runtime.start_red_team(request.mode)


@app.post("/api/policy-pack/select", response_model=PolicyPackSelectResponse)
async def policy_pack_select(
    request: PolicyPackSelectRequest,
    runtime: PrometheusRuntime = Depends(get_runtime),
) -> PolicyPackSelectResponse:
    return await runtime.select_policy_pack(request)


@app.post("/api/review/action", response_model=ReviewQueueActionResponse)
async def review_action(
    request: ReviewQueueActionRequest,
    runtime: PrometheusRuntime = Depends(get_runtime),
) -> ReviewQueueActionResponse:
    return await runtime.apply_review_action(request)


@app.get("/api/stream/events")
async def stream_events(
    runtime: PrometheusRuntime = Depends(get_runtime),
) -> StreamingResponse:
    return StreamingResponse(
        runtime.ping_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@app.post("/api/tribunal/evaluate", response_model=TribunalDecision)
async def tribunal_evaluate(
    request: TribunalEvaluateRequest,
    runtime: PrometheusRuntime = Depends(get_runtime),
) -> TribunalDecision:
    return await runtime.evaluate_request(request)


@app.post("/api/audit/report", response_model=AuditReportResponse)
async def audit_report(
    request: AuditReportRequest,
    runtime: PrometheusRuntime = Depends(get_runtime),
) -> AuditReportResponse:
    return await runtime.build_audit_report(request)


@app.post("/api/audit/report/markdown", response_model=AuditReportExport)
async def audit_report_markdown(
    request: AuditReportRequest,
    runtime: PrometheusRuntime = Depends(get_runtime),
) -> AuditReportExport:
    return await runtime.export_audit_report(request, format_name="markdown")


@app.post("/api/audit/report/html", response_model=AuditReportExport)
async def audit_report_html(
    request: AuditReportRequest,
    runtime: PrometheusRuntime = Depends(get_runtime),
) -> AuditReportExport:
    return await runtime.export_audit_report(request, format_name="html")


@app.post("/api/audit/bundle", response_model=AuditBundleResponse)
async def audit_bundle(
    request: AuditReportRequest,
    runtime: PrometheusRuntime = Depends(get_runtime),
) -> AuditBundleResponse:
    return await runtime.build_audit_bundle(request)


@app.post("/api/lobstertrap/inspect", response_model=LobsterTrapInspectResponse)
async def lobstertrap_inspect(
    request: LobsterTrapInspectRequest,
    runtime: PrometheusRuntime = Depends(get_runtime),
) -> LobsterTrapInspectResponse:
    return await runtime.inspect_prompt(request)


@app.get("/api/lobstertrap/debug", response_model=LobsterTrapDebugResponse)
async def lobstertrap_debug(
    runtime: PrometheusRuntime = Depends(get_runtime),
) -> LobsterTrapDebugResponse:
    return await runtime.lobstertrap_debug()


@app.get("/api/gateway/permissions", response_model=GatewayPermissionMatrix)
async def gateway_permissions(
    runtime: PrometheusRuntime = Depends(get_runtime),
) -> GatewayPermissionMatrix:
    return await runtime.gateway_permissions()


@app.get("/api/gateway/tool-calls", response_model=list[ToolCallDecision])
async def gateway_tool_calls(
    runtime: PrometheusRuntime = Depends(get_runtime),
) -> list[ToolCallDecision]:
    return await runtime.list_tool_calls()


@app.get("/api/gateway/tool-calls/{request_id}", response_model=ToolCallDecision)
async def gateway_tool_call_detail(
    request_id: str,
    runtime: PrometheusRuntime = Depends(get_runtime),
) -> ToolCallDecision:
    return await runtime.get_tool_call(request_id)


@app.post("/api/gateway/tool-call", response_model=ToolCallDecision)
async def gateway_tool_call(
    request: ToolCallRequest,
    include_raw: bool = Query(default=False, alias="includeRaw"),
    runtime: PrometheusRuntime = Depends(get_runtime),
) -> ToolCallDecision:
    decision = await runtime.execute_tool_call(request)
    return _compact_tool_call_response(decision, include_raw=include_raw)


@app.post("/api/gateway/replay/{request_id}", response_model=ToolCallDecision)
async def gateway_replay(
    request_id: str,
    runtime: PrometheusRuntime = Depends(get_runtime),
) -> ToolCallDecision:
    return await runtime.replay_tool_call(request_id)


@app.post("/api/documents/inspect", response_model=DocumentInspectResponse)
async def document_inspect(
    request: DocumentInspectRequest,
    include_raw: bool = Query(default=False, alias="includeRaw"),
    runtime: PrometheusRuntime = Depends(get_runtime),
) -> DocumentInspectResponse:
    response = await runtime.inspect_document(request)
    return _compact_document_response(response, include_raw=include_raw)


@app.post("/api/threat-intel/analyze", response_model=ThreatIntelRunResult)
async def threat_intel_analyze(
    request: ThreatIntelInput,
    include_raw: bool = Query(default=False, alias="includeRaw"),
    runtime: PrometheusRuntime = Depends(get_runtime),
) -> ThreatIntelRunResult:
    response = await runtime.analyze_threat_intel(request)
    return _compact_threat_intel_response(response, include_raw=include_raw)


@app.get("/api/threat-intel/runs", response_model=list[ThreatIntelRunSummary])
async def threat_intel_runs(
    runtime: PrometheusRuntime = Depends(get_runtime),
) -> list[ThreatIntelRunSummary]:
    return await runtime.list_threat_intel_runs()


@app.get("/api/threat-intel/runs/{run_id}", response_model=ThreatIntelRunResult)
async def threat_intel_run_detail(
    run_id: str,
    include_raw: bool = Query(default=False, alias="includeRaw"),
    runtime: PrometheusRuntime = Depends(get_runtime),
) -> ThreatIntelRunResult:
    response = await runtime.get_threat_intel_run(run_id)
    return _compact_threat_intel_response(response, include_raw=include_raw)


@app.post("/api/scenarios/run", response_model=DashboardSnapshot)
async def run_scenario(
    request: ScenarioRunRequest,
    runtime: PrometheusRuntime = Depends(get_runtime),
) -> DashboardSnapshot:
    return await runtime.run_scenario(request)
