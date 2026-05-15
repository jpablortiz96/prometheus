"use client";

import type {
  AuditBundle,
  AuditReportArchiveItem,
  AuditReportExport,
  AuditReportRequest,
  DashboardSnapshot,
  DocumentInspectRequest,
  DocumentInspectResponse,
  IncidentDetail,
  IncidentSummary,
  IntegrationStatus,
  LobsterTrapInspectRequest,
  LobsterTrapInspectResponse,
  ScenarioRecord,
  ToolCallDecisionRecord,
  ToolCallRequest,
} from "@prometheus/shared";
import { useEffect, useRef, useState } from "react";

import {
  applyReviewAction,
  executeToolCall,
  fetchAuditReports,
  fetchIncidentDetail,
  fetchIncidents,
  fetchIntegrationStatus,
  fetchScenarios,
  fetchSnapshot,
  generateAuditBundle,
  generateAuditReport,
  inspectDocument,
  inspectWithLobsterTrap,
  replayToolCall,
  runScenario,
  selectPolicyPack,
  triggerRedTeam,
} from "../lib/api";
import {
  applyLocalPolicyPack,
  applyLocalReviewAction,
  applyLocalScenario,
  applyLocalScenarioById,
  buildLocalAuditReport,
  buildLocalAuditBundle,
  createFallbackSnapshot,
  createLocalTribunal,
  getLocalScenario,
  inspectLocalPrompt,
  listLocalScenarios,
} from "../lib/fallback-data";

type SequenceMode = "drill" | "demo";
type ReviewAction = "approved" | "denied" | "quarantined" | "escalated";
type FetchState = "idle" | "success" | "error";

function clearTimers(timers: number[]) {
  timers.forEach((timer) => window.clearTimeout(timer));
  timers.splice(0, timers.length);
}

function stampSnapshot(snapshot: DashboardSnapshot, updates: Partial<DashboardSnapshot>): DashboardSnapshot {
  return {
    ...snapshot,
    ...updates,
    lastUpdated: new Date().toISOString(),
  };
}

function describeError(error: unknown) {
  if (error instanceof Error) {
    return error.message;
  }
  return "Unknown error";
}

export function useDashboardRuntime(apiBaseUrl: string) {
  const [snapshot, setSnapshot] = useState<DashboardSnapshot>(() => createFallbackSnapshot());
  const [apiAvailable, setApiAvailable] = useState(false);
  const [integrationStatus, setIntegrationStatus] = useState<IntegrationStatus | null>(null);
  const [integrationStatusFetchState, setIntegrationStatusFetchState] = useState<FetchState>("idle");
  const [integrationStatusError, setIntegrationStatusError] = useState<string | null>(null);
  const [snapshotError, setSnapshotError] = useState<string | null>(null);
  const [frontendOrigin, setFrontendOrigin] = useState("unavailable");
  const [incidents, setIncidents] = useState<IncidentSummary[]>([]);
  const [reportArchive, setReportArchive] = useState<AuditReportArchiveItem[]>([]);
  const [scenarios, setScenarios] = useState<ScenarioRecord[]>(() => listLocalScenarios());
  const timersRef = useRef<number[]>([]);
  const countdownRef = useRef<number | null>(null);
  const eventSourceRef = useRef<EventSource | null>(null);
  const mountedRef = useRef(true);

  async function refreshIntegrationStatusState(): Promise<IntegrationStatus | null> {
    try {
      const nextIntegrationStatus = await fetchIntegrationStatus(apiBaseUrl);
      if (!mountedRef.current) {
        return nextIntegrationStatus;
      }
      setIntegrationStatus(nextIntegrationStatus);
      setIntegrationStatusFetchState("success");
      setIntegrationStatusError(null);
      return nextIntegrationStatus;
    } catch (error) {
      if (mountedRef.current) {
        setIntegrationStatus(null);
        setIntegrationStatusFetchState("error");
        setIntegrationStatusError(describeError(error));
      }
      return null;
    }
  }

  async function refreshSnapshotState(): Promise<void> {
    try {
      const [nextSnapshot, nextIncidents, nextReports, nextScenarios] = await Promise.all([
        fetchSnapshot(apiBaseUrl),
        fetchIncidents(apiBaseUrl),
        fetchAuditReports(apiBaseUrl),
        fetchScenarios(apiBaseUrl),
      ]);
      if (!mountedRef.current) {
        return;
      }
      setSnapshot({ ...nextSnapshot, connectionMode: "live" });
      setIncidents(nextIncidents);
      setReportArchive(nextReports);
      setScenarios(nextScenarios);
      setSnapshotError(null);
      setApiAvailable(true);
    } catch (error) {
      if (mountedRef.current) {
        setSnapshotError(describeError(error));
      }
      throw error;
    }
  }

  useEffect(() => {
    mountedRef.current = true;
    setFrontendOrigin(window.location.origin);

    return () => {
      mountedRef.current = false;
    };
  }, []);

  useEffect(() => {
    let active = true;

    async function bootstrap() {
      try {
        await refreshSnapshotState();
      } catch (error) {
        if (!active) {
          return;
        }
        setSnapshotError(describeError(error));
        setSnapshot((current) => ({ ...current, connectionMode: "fallback" }));
        setApiAvailable(false);
        setIncidents(
          createFallbackSnapshot().events.map((event) => ({
            incidentId: event.id,
            title: event.title,
            agentId: event.agentId,
            severity: event.severity,
            decision: event.decision,
            decisionLabel: event.decisionLabel,
            policyPack: event.policyPack,
            riskScore: event.riskScore,
            timestamp: event.timestamp,
          })),
        );
        setReportArchive([]);
        setScenarios(listLocalScenarios());
      }

      await refreshIntegrationStatusState();

      try {
        const source = new EventSource(`${apiBaseUrl}/api/stream/events`);
        eventSourceRef.current = source;
        source.addEventListener("snapshot", (event) => {
          if (!active) {
            return;
          }
          const next = JSON.parse((event as MessageEvent).data) as DashboardSnapshot;
          setSnapshot({ ...next, connectionMode: "live" });
          setApiAvailable(true);
          setIncidents(
            next.events.map((item) => ({
              incidentId: item.id,
              title: item.title,
              agentId: item.agentId,
              severity: item.severity,
              decision: item.decision,
              decisionLabel: item.decisionLabel,
              policyPack: item.policyPack,
              riskScore: item.riskScore,
              timestamp: item.timestamp,
            })),
          );
        });
        source.onerror = () => {
          setApiAvailable(false);
          setSnapshot((current) => ({ ...current, connectionMode: "fallback" }));
          source.close();
        };
      } catch {
        setApiAvailable(false);
      }
    }

    void bootstrap();

    return () => {
      active = false;
      eventSourceRef.current?.close();
      if (countdownRef.current !== null) {
        window.clearInterval(countdownRef.current);
      }
      clearTimers(timersRef.current);
    };
  }, [apiBaseUrl]);

  function runLocalSequence(mode: SequenceMode) {
    clearTimers(timersRef.current);
    if (countdownRef.current !== null) {
      window.clearInterval(countdownRef.current);
    }

    const scenario = getLocalScenario(mode);
    const totalSeconds = mode === "demo" ? 90 : 14;

    setSnapshot((current) =>
      stampSnapshot(current, {
        demoRunning: true,
        demoMode: mode === "demo",
        countdownSeconds: totalSeconds,
        demoStage: mode === "demo" ? "0-10s: Normal operations" : "Red Team drill armed",
        demoProgressPercent: 0,
        reportReady: false,
        activeTribunal: null,
        statusMessage:
          mode === "demo"
            ? "Normal operations. Agents are stable and trust posture is healthy."
            : "Red Team drill armed. Watcher is locking onto the first attack path.",
      }),
    );

    countdownRef.current = window.setInterval(() => {
      setSnapshot((current) => ({
        ...current,
        countdownSeconds: Math.max(current.countdownSeconds - 1, 0),
      }));
    }, 1_000);

    if (mode === "demo") {
      timersRef.current.push(
        window.setTimeout(() => {
          setSnapshot((current) =>
            stampSnapshot(current, {
              demoStage: "10-25s: Document-borne attack enters",
              demoProgressPercent: 20,
              countdownSeconds: 80,
              statusMessage:
                "Indirect prompt injection enters through a vendor document instruction.",
              agents: current.agents.map((agent) =>
                agent.id === scenario.agentId
                  ? {
                      ...agent,
                      status: "watching",
                      lastAction: "document instruction entered the ingest path",
                      lastEventAt: "just now",
                    }
                  : agent,
              ),
            }),
          );
        }, 10_000),
      );
      timersRef.current.push(
        window.setTimeout(() => {
          setSnapshot((current) =>
            stampSnapshot(current, {
              demoStage: "25-40s: Watcher flags intent mismatch",
              demoProgressPercent: 40,
              countdownSeconds: 65,
              statusMessage:
                "Watcher flags the suspicious instruction. Lobster Trap-style DPI extracts a declared-vs-detected intent mismatch.",
            }),
          );
        }, 25_000),
      );
      timersRef.current.push(
        window.setTimeout(() => {
          setSnapshot((current) =>
            stampSnapshot(current, {
              demoStage: "40-55s: Prophet detects divergence",
              demoProgressPercent: 60,
              countdownSeconds: 50,
              statusMessage:
                "Prophet predicts document indexing only, but observed behavior attempts a privileged audit pull.",
              agents: current.agents.map((agent) =>
                agent.id === scenario.agentId
                  ? {
                      ...agent,
                      status: "watching",
                      lastAction: "observed privileged_audit_pull",
                      predictedAction: scenario.predictedAction,
                      divergenceScore: 0.91,
                    }
                  : agent,
              ),
            }),
          );
        }, 40_000),
      );
      timersRef.current.push(
        window.setTimeout(() => {
          setSnapshot((current) =>
            stampSnapshot(current, {
              demoStage: "55-70s: Tribunal voting",
              demoProgressPercent: 78,
              countdownSeconds: 35,
              activeTribunal: createLocalTribunal("demo", current),
              statusMessage: "Tribunal opens automatically. Aegis, Themis, and Dike are voting now.",
            }),
          );
        }, 55_000),
      );
      timersRef.current.push(
        window.setTimeout(() => {
          setSnapshot((current) =>
            stampSnapshot(applyLocalScenario(current, "demo"), {
              demoStage: "70-80s: Quarantine sealed",
              demoProgressPercent: 88,
              countdownSeconds: 20,
              statusMessage: "Decision: QUARANTINE + BLOCK TOOL CALL. Human review queue updated.",
            }),
          );
        }, 70_000),
      );
      timersRef.current.push(
        window.setTimeout(() => {
          setSnapshot((current) =>
            stampSnapshot(current, {
              demoStage: "80-90s: Historian seals the report",
              demoProgressPercent: 96,
              countdownSeconds: 10,
              reportReady: true,
              statusMessage:
                "Historian sealed the audit narrative. Generate Regulator Report is now highlighted.",
            }),
          );
        }, 80_000),
      );
      timersRef.current.push(
        window.setTimeout(() => {
          if (countdownRef.current !== null) {
            window.clearInterval(countdownRef.current);
          }
          setSnapshot((current) =>
            stampSnapshot(current, {
              demoRunning: false,
              demoMode: false,
              countdownSeconds: 0,
              demoStage: "Demo complete",
              demoProgressPercent: 100,
              reportReady: true,
              statusMessage:
                "Judge demo complete. Prometheus showed attack detection, tribunal reasoning, and enterprise-ready audit output.",
            }),
          );
        }, 90_000),
      );
      return;
    }

    timersRef.current.push(
      window.setTimeout(() => {
        setSnapshot((current) =>
          stampSnapshot(current, {
            countdownSeconds: 12,
            demoProgressPercent: 18,
            statusMessage: `${scenario.name}: attack starts and Watcher begins inspection.`,
          }),
        );
      }, 1_000),
    );
    timersRef.current.push(
      window.setTimeout(() => {
        setSnapshot((current) =>
          stampSnapshot(current, {
            countdownSeconds: 9,
            demoProgressPercent: 35,
            statusMessage: `${scenario.name}: Watcher inspects prompt, policy rules, and tool path metadata.`,
          }),
        );
      }, 3_000),
    );
    timersRef.current.push(
      window.setTimeout(() => {
        setSnapshot((current) =>
          stampSnapshot(current, {
            countdownSeconds: 7,
            demoProgressPercent: 52,
            statusMessage: `${scenario.name}: Prophet predicts ${scenario.predictedAction}; observed behavior diverges.`,
          }),
        );
      }, 5_000),
    );
    timersRef.current.push(
      window.setTimeout(() => {
        setSnapshot((current) =>
          stampSnapshot(current, {
            countdownSeconds: 5,
            demoProgressPercent: 72,
            activeTribunal: createLocalTribunal("drill", current),
            statusMessage: `${scenario.name}: Tribunal opens and three judges vote.`,
          }),
        );
      }, 7_000),
    );
    timersRef.current.push(
      window.setTimeout(() => {
        setSnapshot((current) =>
          stampSnapshot(applyLocalScenario(current, "drill"), {
            countdownSeconds: 2,
            demoProgressPercent: 90,
          }),
        );
      }, 10_000),
    );
    timersRef.current.push(
      window.setTimeout(() => {
        if (countdownRef.current !== null) {
          window.clearInterval(countdownRef.current);
        }
        setSnapshot((current) =>
          stampSnapshot(current, {
            demoRunning: false,
            countdownSeconds: 0,
            demoStage: "Red Team drill complete",
            demoProgressPercent: 100,
            reportReady: true,
            statusMessage:
              "Red Team drill complete. Historian preserved the enterprise incident narrative.",
          }),
        );
      }, 14_000),
    );
  }

  async function refreshFromApi() {
    await refreshSnapshotState();
    await refreshIntegrationStatusState();
  }

  async function runSequence(mode: SequenceMode) {
    if (apiAvailable) {
      try {
        const response = await triggerRedTeam(apiBaseUrl, mode);
        if (response.started) {
          return;
        }
      } catch {
        setApiAvailable(false);
      }
    }

    runLocalSequence(mode);
  }

  async function changePolicyPack(policyPackId: string) {
    if (apiAvailable) {
      try {
        await selectPolicyPack(apiBaseUrl, policyPackId);
        await refreshFromApi();
        return;
      } catch {
        setApiAvailable(false);
      }
    }

    setSnapshot((current) => applyLocalPolicyPack(current, policyPackId));
  }

  async function review(eventId: string, action: ReviewAction) {
    if (apiAvailable) {
      try {
        await applyReviewAction(apiBaseUrl, eventId, action);
        await refreshFromApi();
        return;
      } catch {
        setApiAvailable(false);
      }
    }

    setSnapshot((current) => applyLocalReviewAction(current, eventId, action));
  }

  async function generateReport(
    request: AuditReportRequest,
    format: "markdown" | "html",
  ): Promise<AuditReportExport> {
    if (apiAvailable) {
      try {
        return await generateAuditReport(apiBaseUrl, format, request);
      } catch {
        setApiAvailable(false);
      }
    }

    const event =
      snapshot.events.find((item) => item.id === request.incidentId) ??
      snapshot.events.find((item) => item.scenarioId === request.scenarioId) ??
      snapshot.events[0];
    return buildLocalAuditReport(snapshot, event, format);
  }

  async function generateBundle(
    request: AuditReportRequest,
  ): Promise<AuditBundle> {
    if (apiAvailable) {
      try {
        const bundle = await generateAuditBundle(apiBaseUrl, request);
        await refreshFromApi();
        return bundle;
      } catch {
        setApiAvailable(false);
      }
    }

    const event =
      snapshot.events.find((item) => item.id === request.incidentId) ??
      snapshot.events.find((item) => item.scenarioId === request.scenarioId) ??
      snapshot.events[0];
    return buildLocalAuditBundle(snapshot, event);
  }

  async function loadIncident(incidentId: string): Promise<IncidentDetail | null> {
    if (apiAvailable) {
      try {
        return await fetchIncidentDetail(apiBaseUrl, incidentId);
      } catch {
        setApiAvailable(false);
      }
    }

    const event = snapshot.events.find((item) => item.id === incidentId);
    if (!event || !snapshot.activeIncident) {
      return null;
    }
    return {
      incident: snapshot.activeIncident,
      event,
      reports: reportArchive.filter((item) => item.incidentId === incidentId),
    };
  }

  async function inspectPrompt(request: LobsterTrapInspectRequest): Promise<LobsterTrapInspectResponse> {
    if (apiAvailable) {
      try {
        return await inspectWithLobsterTrap(apiBaseUrl, request);
      } catch {
        setApiAvailable(false);
      }
    }
    return inspectLocalPrompt(snapshot, request);
  }

  async function executeScenario(scenarioId: string) {
    if (apiAvailable) {
      try {
        const next = await runScenario(apiBaseUrl, { scenarioId });
        setSnapshot({ ...next, connectionMode: "live" });
        await refreshFromApi();
        return;
      } catch {
        setApiAvailable(false);
      }
    }

    setSnapshot((current) => applyLocalScenarioById(current, scenarioId));
  }

  async function runToolGatewayCall(
    request: ToolCallRequest,
  ): Promise<ToolCallDecisionRecord> {
    if (apiAvailable) {
      try {
        const decision = await executeToolCall(apiBaseUrl, request);
        await refreshFromApi();
        return decision;
      } catch {
        setApiAvailable(false);
      }
    }

    return {
      requestId: `local_${Date.now()}`,
      agentId: request.agentId,
      toolName: request.toolName,
      declaredIntent: request.declaredIntent,
      detectedIntent: request.declaredIntent,
      predictedAction: request.toolName,
      observedAction: request.toolName,
      dpiSource: "simulated",
      dpiMode: "simulated",
      decision: "BLOCK",
      toolExecuted: false,
      riskScore: 0.88,
      matchedRules: ["deterministic_fallback"],
      reason: "Frontend is running in deterministic fallback mode. Backend tool gateway is unavailable.",
      rawLobstertrapOutput: null,
      tribunalVotes: [],
      auditHash: "fallback",
      createdAt: new Date().toISOString(),
      permissionEvaluation: {
        agentId: request.agentId,
        toolName: request.toolName,
        policyPack: request.policyPack,
        permissionState: "quarantine",
        allowed: false,
        requiresHumanReview: request.requiresHumanReview ?? false,
        externalEgress: false,
        dataClassification: "internal",
        reason: "Fallback mode",
        matchedRestrictions: ["deterministic_fallback"],
      },
      toolResult: null,
      sideEffectPrevented: `${request.toolName} was not executed in fallback mode.`,
      sideEffectPreventedFlag: true,
      sourceEventId: null,
    };
  }

  async function replayGatewayCall(requestId: string): Promise<ToolCallDecisionRecord | null> {
    if (apiAvailable) {
      try {
        const decision = await replayToolCall(apiBaseUrl, requestId);
        await refreshFromApi();
        return decision;
      } catch {
        setApiAvailable(false);
      }
    }
    return null;
  }

  async function inspectDocumentAttack(
    request: DocumentInspectRequest,
  ): Promise<DocumentInspectResponse> {
    if (apiAvailable) {
      try {
        const result = await inspectDocument(apiBaseUrl, request);
        await refreshFromApi();
        return result;
      } catch {
        setApiAvailable(false);
      }
    }
    const inspection = inspectLocalPrompt(snapshot, {
      prompt: request.documentContent,
      declaredIntent: request.declaredIntent,
      agentId: request.agentId,
      policyPack: request.policyPack,
    });
    return {
      documentName: request.documentName,
      contentExcerpt: request.documentContent.slice(0, 220),
      toolDecision: {
        requestId: `local_doc_${Date.now()}`,
        agentId: request.agentId,
        toolName: request.toolName,
        declaredIntent: request.declaredIntent,
        detectedIntent: inspection.inspection.detectedIntent,
        predictedAction: request.toolName,
        observedAction: request.toolName,
        dpiSource: inspection.inspection.dpiSource,
        dpiMode: inspection.inspection.dpiMode,
        decision: "QUARANTINE",
        toolExecuted: false,
        riskScore: inspection.inspection.riskScore,
        matchedRules: inspection.inspection.matchedPolicyRules,
        reason: "Deterministic fallback document inspection blocked the requested tool path.",
        rawLobstertrapOutput: inspection.inspection.rawLobstertrapOutput,
        tribunalVotes: [],
        auditHash: "fallback",
        createdAt: new Date().toISOString(),
        permissionEvaluation: {
          agentId: request.agentId,
          toolName: request.toolName,
          policyPack: request.policyPack,
          permissionState: "quarantine",
          allowed: false,
          requiresHumanReview: true,
          externalEgress: false,
          dataClassification: "internal",
          reason: "Fallback mode",
          matchedRestrictions: inspection.inspection.matchedPolicyRules,
        },
        toolResult: null,
        sideEffectPrevented: `${request.toolName} was blocked before execution.`,
        sideEffectPreventedFlag: true,
        sourceEventId: null,
      },
      incidentId: null,
      auditHash: "fallback",
    };
  }

  function clearTribunal() {
    setSnapshot((current) => stampSnapshot(current, { activeTribunal: null }));
  }

  return {
    snapshot,
    apiAvailable,
    integrationStatus,
    integrationStatusFetchState,
    integrationStatusError,
    snapshotError,
    frontendOrigin,
    incidents,
    reportArchive,
    scenarios,
    runDrill: () => runSequence("drill"),
    runDemo: () => runSequence("demo"),
    selectPolicyPack: changePolicyPack,
    applyReviewAction: review,
    generateReport,
    generateBundle,
    loadIncident,
    inspectPrompt,
    runToolCall: runToolGatewayCall,
    replayToolCall: replayGatewayCall,
    inspectDocument: inspectDocumentAttack,
    runScenario: executeScenario,
    refreshFromApi,
    refreshIntegrationStatus: refreshIntegrationStatusState,
    clearTribunal,
  };
}
