import type {
  AuditBundle,
  AuditReportArchiveItem,
  AuditReportExport,
  AuditReportRequest,
  DashboardSnapshot,
  DocumentInspectRequest,
  DocumentInspectResponse,
  GatewayPermissionMatrix,
  IncidentDetail,
  IncidentSummary,
  IntegrationStatus,
  LobsterTrapInspectRequest,
  LobsterTrapInspectResponse,
  PolicyPackSelectResponse,
  RedTeamRunResponse,
  ReviewQueueActionResponse,
  ScenarioRecord,
  ScenarioRunRequest,
  ThreatIntelInput,
  ThreatIntelRunResult,
  ThreatIntelRunSummary,
  ToolCallDecisionRecord,
  ToolCallRequest,
} from "@prometheus/shared";

async function requestJson<T>(input: string, init?: RequestInit): Promise<T> {
  const headers = new Headers(init?.headers);
  const hasBody = init?.body !== undefined && init?.body !== null;

  if (hasBody && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  const response = await fetch(input, {
    ...init,
    headers,
  });

  if (!response.ok) {
    let detail = "";
    try {
      detail = await response.text();
    } catch {
      detail = "";
    }
    const suffix = detail ? ` - ${detail}` : "";
    throw new Error(`Request failed: ${response.status} ${response.statusText}${suffix}`);
  }

  return (await response.json()) as T;
}

export function fetchSnapshot(apiBaseUrl: string) {
  return requestJson<DashboardSnapshot>(`${apiBaseUrl}/api/snapshot`);
}

export function fetchIntegrationStatus(apiBaseUrl: string) {
  return requestJson<IntegrationStatus>(`${apiBaseUrl}/api/integrations/status`);
}

export function fetchIncidents(apiBaseUrl: string) {
  return requestJson<IncidentSummary[]>(`${apiBaseUrl}/api/incidents`);
}

export function fetchIncidentDetail(apiBaseUrl: string, incidentId: string) {
  return requestJson<IncidentDetail>(`${apiBaseUrl}/api/incidents/${incidentId}`);
}

export function fetchAuditReports(apiBaseUrl: string) {
  return requestJson<AuditReportArchiveItem[]>(`${apiBaseUrl}/api/audit/reports`);
}

export function fetchScenarios(apiBaseUrl: string) {
  return requestJson<ScenarioRecord[]>(`${apiBaseUrl}/api/scenarios`);
}

export function fetchGatewayPermissions(apiBaseUrl: string) {
  return requestJson<GatewayPermissionMatrix>(`${apiBaseUrl}/api/gateway/permissions`);
}

export function fetchToolCalls(apiBaseUrl: string) {
  return requestJson<ToolCallDecisionRecord[]>(`${apiBaseUrl}/api/gateway/tool-calls`);
}

export function triggerRedTeam(apiBaseUrl: string, mode: "drill" | "demo") {
  return requestJson<RedTeamRunResponse>(`${apiBaseUrl}/api/red-team/run`, {
    method: "POST",
    body: JSON.stringify({ mode }),
  });
}

export function selectPolicyPack(apiBaseUrl: string, policyPackId: string) {
  return requestJson<PolicyPackSelectResponse>(`${apiBaseUrl}/api/policy-pack/select`, {
    method: "POST",
    body: JSON.stringify({ policyPackId }),
  });
}

export function applyReviewAction(
  apiBaseUrl: string,
  eventId: string,
  action: "approved" | "denied" | "quarantined" | "escalated",
) {
  return requestJson<ReviewQueueActionResponse>(`${apiBaseUrl}/api/review/action`, {
    method: "POST",
    body: JSON.stringify({ eventId, action }),
  });
}

export function generateAuditReport(
  apiBaseUrl: string,
  format: "markdown" | "html",
  request: AuditReportRequest,
) {
  return requestJson<AuditReportExport>(`${apiBaseUrl}/api/audit/report/${format}`, {
    method: "POST",
    body: JSON.stringify(request),
  });
}

export function generateAuditBundle(
  apiBaseUrl: string,
  request: AuditReportRequest,
) {
  return requestJson<AuditBundle>(`${apiBaseUrl}/api/audit/bundle`, {
    method: "POST",
    body: JSON.stringify(request),
  });
}

export function inspectWithLobsterTrap(
  apiBaseUrl: string,
  request: LobsterTrapInspectRequest,
) {
  return requestJson<LobsterTrapInspectResponse>(`${apiBaseUrl}/api/lobstertrap/inspect`, {
    method: "POST",
    body: JSON.stringify(request),
  });
}

export function executeToolCall(
  apiBaseUrl: string,
  request: ToolCallRequest,
) {
  return requestJson<ToolCallDecisionRecord>(`${apiBaseUrl}/api/gateway/tool-call`, {
    method: "POST",
    body: JSON.stringify(request),
  });
}

export function replayToolCall(
  apiBaseUrl: string,
  requestId: string,
) {
  return requestJson<ToolCallDecisionRecord>(`${apiBaseUrl}/api/gateway/replay/${requestId}`, {
    method: "POST",
  });
}

export function inspectDocument(
  apiBaseUrl: string,
  request: DocumentInspectRequest,
) {
  return requestJson<DocumentInspectResponse>(`${apiBaseUrl}/api/documents/inspect`, {
    method: "POST",
    body: JSON.stringify(request),
  });
}

export function runScenario(
  apiBaseUrl: string,
  request: ScenarioRunRequest,
) {
  return requestJson<DashboardSnapshot>(`${apiBaseUrl}/api/scenarios/run`, {
    method: "POST",
    body: JSON.stringify(request),
  });
}

export function analyzeThreatIntel(
  apiBaseUrl: string,
  request: ThreatIntelInput,
) {
  return requestJson<ThreatIntelRunResult>(`${apiBaseUrl}/api/threat-intel/analyze`, {
    method: "POST",
    body: JSON.stringify(request),
  });
}

export function fetchThreatIntelRuns(apiBaseUrl: string) {
  return requestJson<ThreatIntelRunSummary[]>(`${apiBaseUrl}/api/threat-intel/runs`);
}

export function fetchThreatIntelRun(apiBaseUrl: string, runId: string) {
  return requestJson<ThreatIntelRunResult>(`${apiBaseUrl}/api/threat-intel/runs/${runId}`);
}
