"use client";

import type {
  AgentRecord,
  AuditBundle,
  AuditReportArchiveItem,
  AuditReportExport,
  DashboardSnapshot,
  EventRecord,
  IncidentSummary,
  KnowledgeGraph,
  KnowledgeNode,
  ReviewQueueItem,
  TribunalDecision,
} from "@prometheus/shared";
import { Fragment, startTransition, useEffect, useState } from "react";

import { useDashboardRuntime } from "../hooks/use-dashboard-runtime";
import {
  getGeminiStatusCopy,
  getLobsterTrapStatusCopy,
  splitTenantLabel,
} from "../lib/integration-status";

function SigilIcon() {
  return (
    <svg className="brand-sigil" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path d="M12 2v20" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
      <path d="M5 7s3-2 7-2 7 2 7 2" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
      <path d="M4 13s3-2 8-2 8 2 8 2" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
      <path d="M6 19s3-2 6-2 6 2 6 2" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
      <circle cx="12" cy="2.5" r="1.5" fill="currentColor" />
    </svg>
  );
}

function StreamIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <circle cx="12" cy="12" r="3" stroke="currentColor" strokeWidth="1.5" />
      <path d="M12 1v6M12 17v6M1 12h6M17 12h6" stroke="currentColor" strokeWidth="1.5" />
      <path
        d="M4.22 4.22l4.24 4.24M15.54 15.54l4.24 4.24M4.22 19.78l4.24-4.24M15.54 8.46l4.24-4.24"
        stroke="currentColor"
        strokeWidth="1.5"
      />
    </svg>
  );
}

function formatDelta(delta: number) {
  if (delta > 0) {
    return `+${delta}`;
  }
  if (delta < 0) {
    return `-${Math.abs(delta)}`;
  }
  return "0";
}

const dashboardTimeFormatter = new Intl.DateTimeFormat("en-GB", {
  hour: "2-digit",
  minute: "2-digit",
  hour12: false,
  timeZone: "UTC",
});

function formatTime(timestamp: string) {
  const date = new Date(timestamp);
  if (Number.isNaN(date.getTime())) {
    return "--:--";
  }
  return dashboardTimeFormatter.format(date);
}

function titleCase(value: string) {
  return value.replace(/_/g, " ").replace(/\b\w/g, (char) => char.toUpperCase());
}

function statusClass(status: AgentRecord["status"]) {
  return `status-${status}`;
}

function severityClass(severity: EventRecord["severity"]) {
  return `severity-${severity}`;
}

function metricEmphasisClass(emphasis: DashboardSnapshot["enterpriseMetrics"][number]["emphasis"]) {
  return `metric-${emphasis}`;
}

function Sparkline({ points }: { points: number[] }) {
  const min = Math.min(...points);
  const max = Math.max(...points);
  const range = Math.max(max - min, 1);
  const path = points
    .map((point, index) => {
      const x = (index / Math.max(points.length - 1, 1)) * 100;
      const y = 24 - ((point - min) / range) * 18;
      return `${x},${y}`;
    })
    .join(" ");

  return (
    <svg className="sparkline" viewBox="0 0 100 28" preserveAspectRatio="none" aria-hidden="true">
      <polyline points={path} fill="none" stroke="currentColor" strokeWidth="1.6" />
    </svg>
  );
}

function DivergenceRing({
  value,
  severity,
}: {
  value: number;
  severity: EventRecord["severity"];
}) {
  const dashOffset = 88 - Math.max(0, Math.min(0.99, value)) * 88;
  return (
    <div className="divergence-ring">
      <svg width="40" height="40" aria-hidden="true">
        <circle cx="20" cy="20" r="14" fill="none" stroke="var(--bone-500)" strokeWidth="2" />
        <circle
          cx="20"
          cy="20"
          r="14"
          fill="none"
          stroke={`var(${
            severity === "critical"
              ? "--threat-500"
              : severity === "high"
                ? "--watch-500"
                : "--trust-500"
          })`}
          strokeWidth="2"
          strokeDasharray="88"
          strokeDashoffset={dashOffset}
          strokeLinecap="round"
        />
      </svg>
      <div className="divergence-value">{value.toFixed(2)}</div>
    </div>
  );
}

function JudgeCaption({ children }: { children: React.ReactNode }) {
  return <p className="judge-caption">{children}</p>;
}

function KnowledgeGraphPanel({
  graph,
  selectedNodeId,
  onSelectNode,
}: {
  graph: KnowledgeGraph;
  selectedNodeId: string | null;
  onSelectNode: (nodeId: string) => void;
}) {
  const nodeMap = new Map(graph.nodes.map((node) => [node.id, node]));

  return (
    <svg width="100%" height="100%" viewBox="0 0 980 420" className="graph-svg">
      <g>
        {graph.edges.map((edge) => {
          const from = nodeMap.get(edge.from);
          const to = nodeMap.get(edge.to);
          if (!from || !to) {
            return null;
          }

          const isHot = edge.from === selectedNodeId || edge.to === selectedNodeId;
          return (
            <line
              key={`${edge.from}-${edge.to}`}
              x1={from.x}
              y1={from.y}
              x2={to.x}
              y2={to.y}
              className={`graph-edge edge-${edge.type}${isHot ? " is-hot" : ""}`}
            />
          );
        })}
      </g>
      <g>
        {graph.nodes.map((node) => {
          const isSelected = node.id === selectedNodeId;
          const classes = `graph-node graph-${node.type}${node.emphasis ? " emphasis" : ""}${isSelected ? " selected" : ""}`;

          return (
            <g
              key={node.id}
              role="button"
              tabIndex={0}
              className="graph-node-hit"
              onClick={() => onSelectNode(node.id)}
              onKeyDown={(event) => {
                if (event.key === "Enter" || event.key === " ") {
                  event.preventDefault();
                  onSelectNode(node.id);
                }
              }}
            >
              {node.type === "agent" ? (
                <circle cx={node.x} cy={node.y} r={node.emphasis ? 12 : 9} className={classes} />
              ) : null}
              {node.type === "tool" ? (
                <rect x={node.x - 9} y={node.y - 9} width="18" height="18" rx="2" className={classes} />
              ) : null}
              {node.type === "data_store" ? (
                <rect x={node.x - 12} y={node.y - 8} width="24" height="16" className={classes} />
              ) : null}
              {node.type === "policy_rule" ? (
                <polygon
                  points={`${node.x},${node.y - 11} ${node.x + 11},${node.y} ${node.x},${node.y + 11} ${node.x - 11},${node.y}`}
                  className={classes}
                />
              ) : null}
              {node.type === "incident" ? (
                <polygon
                  points={`${node.x},${node.y - 10} ${node.x + 10},${node.y + 10} ${node.x - 10},${node.y + 10}`}
                  className={classes}
                />
              ) : null}
              <text x={node.x + 16} y={node.y + 4} className={`graph-label${isSelected ? " selected" : ""}`}>
                {node.label}
              </text>
            </g>
          );
        })}
      </g>
      <g className="graph-legend">
        <circle cx="28" cy="396" r="5" className="graph-node graph-agent" />
        <text x="40" y="400" className="graph-label subtle">
          Agents
        </text>
        <rect x="114" y="390" width="12" height="12" rx="2" className="graph-node graph-tool" />
        <text x="134" y="400" className="graph-label subtle">
          Tools
        </text>
        <rect x="194" y="392" width="18" height="10" className="graph-node graph-data_store" />
        <text x="220" y="400" className="graph-label subtle">
          Data stores
        </text>
        <polygon points="328,390 338,400 328,410 318,400" className="graph-node graph-policy_rule" />
        <text x="350" y="400" className="graph-label subtle">
          Policy rules
        </text>
        <polygon points="470,390 480,410 460,410" className="graph-node graph-incident" />
        <text x="492" y="400" className="graph-label subtle">
          Incidents
        </text>
      </g>
    </svg>
  );
}

function TribunalModal({
  tribunal,
  onClose,
}: {
  tribunal: TribunalDecision;
  onClose: () => void;
}) {
  return (
    <div className="overlay-shell">
      <div className="tribunal-modal">
        <div className="overlay-head">
          <div>
            <div className="eyebrow">Tribunal</div>
            <h2 className="overlay-title">Decision pending for {tribunal.agentId}</h2>
          </div>
          <button className="btn-ghost" type="button" onClick={onClose}>
            Close
          </button>
        </div>
        <div className="tribunal-grid">
          {tribunal.judges.map((judge) => (
            <article className="judge-card" key={`${tribunal.scenarioId}-${judge.judge}`}>
              <div className="judge-badge">{judge.judge.slice(0, 1)}</div>
              <div className="judge-name">{judge.judge}</div>
              <div className="judge-role">{judge.role}</div>
              <div className={`judge-vote vote-${judge.vote.toLowerCase()}`}>{judge.vote}</div>
              <p className="judge-reasoning">{judge.reasoning}</p>
            </article>
          ))}
        </div>
        <div className={`tribunal-consensus consensus-${tribunal.consensus.toLowerCase()}`}>
          <div>
            <div className="eyebrow">Consensus</div>
            <div className="consensus-value">{tribunal.consensus}</div>
          </div>
          <div>
            <div className="eyebrow">Latency</div>
            <div className="consensus-meta">{tribunal.latencyMs}ms</div>
          </div>
          <p className="tribunal-explanation">{tribunal.explanation}</p>
        </div>
      </div>
    </div>
  );
}

function ReportModal({
  report,
  onClose,
  onCopy,
  onDownload,
  onFormatChange,
  loading,
}: {
  report: AuditReportExport | null;
  onClose: () => void;
  onCopy: () => void;
  onDownload: () => void;
  onFormatChange: (format: "markdown" | "html") => void;
  loading: boolean;
}) {
  return (
    <div className="overlay-shell">
      <div className="report-modal">
        <div className="overlay-head">
          <div>
            <div className="eyebrow">Audit export</div>
            <h2 className="overlay-title">{report?.title ?? "Generate Regulator Report"}</h2>
          </div>
          <button className="btn-ghost" type="button" onClick={onClose}>
            Close
          </button>
        </div>
        <div className="report-toolbar">
          <div className="format-switch">
            <button
              className={`format-pill${report?.format === "markdown" ? " active" : ""}`}
              type="button"
              onClick={() => onFormatChange("markdown")}
              disabled={loading}
            >
              Markdown
            </button>
            <button
              className={`format-pill${report?.format === "html" ? " active" : ""}`}
              type="button"
              onClick={() => onFormatChange("html")}
              disabled={loading}
            >
              HTML
            </button>
          </div>
          <div className="report-actions">
            <button className="btn-ghost" type="button" onClick={onCopy} disabled={!report || loading}>
              Copy
            </button>
            <button className="btn-redteam" type="button" onClick={onDownload} disabled={!report || loading}>
              Download
            </button>
          </div>
        </div>
        <div className="report-meta">
          <span>Format: {report?.format ?? "pending"}</span>
          <span>Model: {report?.modelUsed ?? "deterministic-demo"}</span>
          <span>File: {report?.fileName ?? "n/a"}</span>
        </div>
        <pre className="report-preview">{loading ? "Generating report..." : report?.content ?? ""}</pre>
      </div>
    </div>
  );
}

function AuditBundleModal({
  bundle,
  onClose,
  onCopyHash,
  onDownload,
}: {
  bundle: AuditBundle | null;
  onClose: () => void;
  onCopyHash: () => void;
  onDownload: (format: "markdown" | "html") => void;
}) {
  return (
    <div className="overlay-shell">
      <div className="report-modal">
        <div className="overlay-head">
          <div>
            <div className="eyebrow">Audit bundle</div>
            <h2 className="overlay-title">{bundle?.incidentId ?? "Generate Audit Bundle"}</h2>
          </div>
          <button className="btn-ghost" type="button" onClick={onClose}>
            Close
          </button>
        </div>
        <div className="report-toolbar">
          <div className="bundle-seal">Historian sealed</div>
          <div className="report-actions">
            <button className="btn-ghost" type="button" onClick={onCopyHash} disabled={!bundle}>
              Copy Hash
            </button>
            <button className="btn-ghost" type="button" onClick={() => onDownload("markdown")} disabled={!bundle}>
              Export .md
            </button>
            <button className="btn-redteam" type="button" onClick={() => onDownload("html")} disabled={!bundle}>
              Export .html
            </button>
          </div>
        </div>
        <div className="report-meta">
          <span>Tenant: {bundle?.tenant ?? "Acme Global Bank"}</span>
          <span>Policy pack: {bundle?.policyPack ?? "finance"}</span>
          <span>Decision: {bundle?.decision ?? "pending"}</span>
        </div>
        <div className="audit-hash-shell">
          <div className="drawer-label">Audit hash</div>
          <code>{bundle?.auditHash ?? "Generating..."}</code>
          <p>{bundle?.tamperNotice ?? "Tamper-evident audit hash generated from canonical incident evidence."}</p>
          <p>Designed for SOC2, HIPAA, Finance, and GDPR review workflows.</p>
        </div>
        <pre className="report-preview">{bundle?.markdownReport ?? ""}</pre>
      </div>
    </div>
  );
}

function EvidenceDrawer({
  event,
  onClose,
}: {
  event: EventRecord | null;
  onClose: () => void;
}) {
  if (!event) {
    return null;
  }

  const lobsterTrapMetadata =
    event.evidence.lobsterTrapMetadata ??
    event.evidence.lobstertrapMetadata ??
    {};
  const lobsterTrapMeta = (
    lobsterTrapMetadata["_lobstertrap"] as Record<string, unknown> | undefined
  ) ?? {};
  const matchedPolicyRules = event.evidence.matchedPolicyRules ?? [];
  const detectedPii = event.evidence.detectedPii ?? [];
  const credentialPatterns = event.evidence.credentialPatterns ?? [];
  const targetDomains = event.evidence.targetDomains ?? [];
  const riskyCommands = event.evidence.riskyCommands ?? [];
  const sensitivePaths = event.evidence.sensitivePaths ?? [];
  const timeline = event.evidence.timeline ?? [];
  const policyFile = String(lobsterTrapMeta.policy_file ?? "unknown");
  const policyRuleCount = String(lobsterTrapMeta.policy_rule_count ?? "unknown");
  const cliExecutionTime = String(lobsterTrapMeta.cli_execution_time_ms ?? "n/a");

  return (
    <aside className="evidence-drawer">
      <div className="drawer-head">
        <div>
          <div className="eyebrow">Evidence drawer</div>
          <h3>{event.title}</h3>
          <div className="evidence-badge">
            {event.evidence.dpiSource === "veea_lobstertrap_cli"
              ? "Inspected by Veea Lobster Trap CLI"
              : "Deterministic fallback inspection"}
          </div>
        </div>
        <button className="btn-ghost" type="button" onClick={onClose}>
          Close
        </button>
      </div>

      <div className="drawer-block">
        <div className="drawer-label">Raw prompt</div>
        <p>{event.evidence.rawPrompt}</p>
      </div>

      <div className="drawer-grid">
        <div className="drawer-card">
          <div className="drawer-label">DPI findings</div>
          <ul>
            {event.evidence.dpiFindings.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </div>
        <div className="drawer-card">
          <div className="drawer-label">Matched policy rules</div>
          <ul>
              {matchedPolicyRules.map((item) => (
                <li key={item}>{item}</li>
              ))}
          </ul>
        </div>
        <div className="drawer-card">
          <div className="drawer-label">Detected PII</div>
            <p>{detectedPii.join(", ") || "none"}</p>
        </div>
        <div className="drawer-card">
          <div className="drawer-label">Credential patterns</div>
            <p>{credentialPatterns.join(", ") || "none"}</p>
        </div>
        <div className="drawer-card">
          <div className="drawer-label">Target domains</div>
            <p>{targetDomains.join(", ") || "none"}</p>
        </div>
        <div className="drawer-card">
          <div className="drawer-label">Risky commands</div>
            <p>{riskyCommands.join(", ") || "none"}</p>
        </div>
        <div className="drawer-card">
          <div className="drawer-label">Sensitive paths</div>
            <p>{sensitivePaths.join(", ") || "none"}</p>
        </div>
        <div className="drawer-card">
          <div className="drawer-label">DPI mode</div>
          <p>{event.evidence.dpiMode}</p>
        </div>
        <div className="drawer-card">
          <div className="drawer-label">Policy file used</div>
          <p>{policyFile}</p>
        </div>
        <div className="drawer-card">
          <div className="drawer-label">Policy rule count</div>
          <p>{policyRuleCount}</p>
        </div>
        <div className="drawer-card">
          <div className="drawer-label">CLI execution time</div>
          <p>{cliExecutionTime}ms</p>
        </div>
        <div className="drawer-card">
          <div className="drawer-label">Fallback status</div>
          <p>{event.evidence.fallbackUsed ? event.evidence.fallbackReason ?? "Fallback active" : "Live CLI inspection"}</p>
        </div>
      </div>

      <div className="drawer-metrics">
        <div>
          <span>Divergence</span>
          <strong>{event.evidence.divergenceScore.toFixed(2)}</strong>
        </div>
        <div>
          <span>Trust delta</span>
          <strong>{formatDelta(event.evidence.trustDelta)}</strong>
        </div>
        <div>
          <span>Recommended action</span>
          <strong>{event.evidence.recommendedAction}</strong>
        </div>
      </div>

      {event.evidence.fallbackUsed ? (
        <div className="drawer-block">
          <div className="drawer-label">Fallback status</div>
          <p>{event.evidence.fallbackReason ?? "Deterministic fallback active."}</p>
        </div>
      ) : null}

      <div className="drawer-block">
        <div className="drawer-label">Timeline</div>
          <ol className="timeline-list">
            {timeline.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ol>
      </div>

      <div className="drawer-block">
        <div className="drawer-label">Raw Lobster Trap output</div>
        <pre className="drawer-json">{event.evidence.rawLobstertrapOutput ?? "No raw CLI output captured."}</pre>
      </div>

      <div className="drawer-block">
        <div className="drawer-label">Raw DPI evidence</div>
          <pre className="drawer-json">{JSON.stringify(lobsterTrapMetadata, null, 2)}</pre>
      </div>
    </aside>
  );
}

export function PrometheusDashboard({ apiBaseUrl }: { apiBaseUrl: string }) {
  const {
    snapshot,
    integrationStatus,
    integrationStatusFetchState,
    integrationStatusError,
    snapshotError,
    frontendOrigin,
    incidents,
    reportArchive,
    runDrill,
    runDemo,
    selectPolicyPack,
    applyReviewAction,
    generateReport,
    generateBundle,
    loadIncident,
    replayToolCall,
    refreshIntegrationStatus,
    clearTribunal,
  } = useDashboardRuntime(apiBaseUrl);
  const [selectedEventId, setSelectedEventId] = useState<string | null>(null);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [evidenceOpen, setEvidenceOpen] = useState(false);
  const [judgeMode, setJudgeMode] = useState(false);
  const [presentationMode, setPresentationMode] = useState(false);
  const [report, setReport] = useState<AuditReportExport | null>(null);
  const [reportOpen, setReportOpen] = useState(false);
  const [reportLoading, setReportLoading] = useState(false);
  const [bundle, setBundle] = useState<AuditBundle | null>(null);
  const [bundleOpen, setBundleOpen] = useState(false);
  const [reviewBusyKey, setReviewBusyKey] = useState<string | null>(null);

  useEffect(() => {
    if (!selectedEventId && snapshot.events[0]) {
      setSelectedEventId(snapshot.events[0].id);
    }
  }, [selectedEventId, snapshot.events]);

  useEffect(() => {
    if (!selectedNodeId && snapshot.knowledgeGraph.nodes[0]) {
      setSelectedNodeId(snapshot.knowledgeGraph.nodes[0].id);
    }
  }, [selectedNodeId, snapshot.knowledgeGraph.nodes]);

  useEffect(() => {
    function handleKeydown(event: KeyboardEvent) {
      if (
        event.target instanceof HTMLInputElement ||
        event.target instanceof HTMLTextAreaElement ||
        event.target instanceof HTMLSelectElement
      ) {
        return;
      }

      const key = event.key.toLowerCase();
      if (key === "d") {
        startTransition(() => void runDemo());
      } else if (key === "r") {
        startTransition(() => void runDrill());
      } else if (key === "j") {
        setJudgeMode((current) => !current);
      } else if (key === "p") {
        setPresentationMode((current) => !current);
      } else if (key === "g") {
        startTransition(() => void requestReport(report?.format ?? "markdown"));
      }
    }

    window.addEventListener("keydown", handleKeydown);
    return () => window.removeEventListener("keydown", handleKeydown);
  }, [report?.format, runDemo, runDrill]);

  const selectedEvent =
    snapshot.events.find((event) => event.id === selectedEventId) ?? snapshot.events[0] ?? null;
  const selectedNode =
    snapshot.knowledgeGraph.nodes.find((node) => node.id === selectedNodeId) ??
    snapshot.knowledgeGraph.nodes[0] ??
    null;
  const activeIncident = snapshot.activeIncident;
  const activePolicy =
    snapshot.policyPacks.find((pack) => pack.id === snapshot.activePolicyPack) ??
    snapshot.policyPacks[0];
  const integrationStatusPending = integrationStatusFetchState === "idle";
  const integrationStatusAvailable =
    integrationStatusFetchState === "success" && integrationStatus !== null;
  const integrationStatusWarning =
    integrationStatusFetchState === "error"
      ? "Frontend could not reach backend status endpoint. Check CORS or NEXT_PUBLIC_API_URL."
      : null;
  const resolvedIntegrationStatus = integrationStatusAvailable ? integrationStatus : null;
  const geminiAvailable = resolvedIntegrationStatus?.geminiAvailable ?? false;
  const geminiStatus = resolvedIntegrationStatus
    ? getGeminiStatusCopy(resolvedIntegrationStatus)
    : integrationStatusPending
      ? {
          headline: "Checking backend status",
          detail: "PROMETHEUS is verifying live Gemini connectivity.",
          streamLabel: "Checking status",
          error: null,
        }
      : {
          headline: "API status unavailable",
          detail: "Live Gemini status could not be loaded.",
          streamLabel: "Status unavailable",
          error: null,
        };
  const lobsterTrapStatus = resolvedIntegrationStatus
    ? getLobsterTrapStatusCopy(resolvedIntegrationStatus)
    : integrationStatusPending
      ? {
          headline: "Checking backend status",
          detail: "PROMETHEUS is verifying live Lobster Trap CLI connectivity.",
          badge: "Checking backend status",
          note: null,
        }
      : {
          headline: "API status unavailable",
          detail: "Live Lobster Trap status could not be loaded.",
          badge: "API status unavailable",
          note: null,
        };
  const auditTrailLabel = resolvedIntegrationStatus
    ? resolvedIntegrationStatus.auditTrailOnline
      ? "Online"
      : "Offline"
    : integrationStatusPending
      ? "Checking status"
      : "Status unavailable";
  const { tenantName, tenantDescriptor } = splitTenantLabel(snapshot.tenantLabel);
  const kpiCards = [
    {
      id: "attacks-blocked",
      label: "Attacks blocked",
      value: snapshot.kpis.attacksBlocked,
      meta: "Blocked before tool execution",
    },
    {
      id: "agents-monitored",
      label: "Agents monitored",
      value: snapshot.kpis.activeAgents,
      meta: "Active governance envelope",
    },
    {
      id: "average-latency",
      label: "Average latency",
      value: snapshot.kpis.averageLatencyMs,
      meta: "End-to-end tribunal path",
      suffix: "ms",
    },
    {
      id: "trust-floor",
      label: "Trust floor",
      value: snapshot.kpis.trustFloor,
      meta: "Lowest active trust score",
    },
    {
      id: "incidents-24h",
      label: "Incidents 24h",
      value: snapshot.kpis.incidents24h,
      meta: "Historian incident ledger",
    },
  ];
  const visibleKpis = presentationMode
    ? kpiCards.filter((card) =>
        ["attacks-blocked", "average-latency", "incidents-24h"].includes(card.id),
      )
    : kpiCards;
  const visibleEnterpriseMetrics = presentationMode
    ? snapshot.enterpriseMetrics.slice(0, 4)
    : snapshot.enterpriseMetrics;

  async function handleReviewAction(item: ReviewQueueItem, action: "approved" | "denied" | "quarantined" | "escalated") {
    const busyKey = `${item.eventId}:${action}`;
    setReviewBusyKey(busyKey);
    try {
      await applyReviewAction(item.eventId, action);
      if (selectedEventId === item.eventId) {
        setEvidenceOpen(true);
      }
    } finally {
      setReviewBusyKey(null);
    }
  }

  async function requestReport(format: "markdown" | "html") {
    setReportLoading(true);
    setReportOpen(true);
    try {
      const nextReport = await generateReport(
        selectedEvent ? { incidentId: selectedEvent.id } : { scenarioId: "indirect_prompt_injection" },
        format,
      );
      setReport(nextReport);
    } finally {
      setReportLoading(false);
    }
  }

  async function requestBundle() {
    setBundleOpen(true);
    const nextBundle = await generateBundle(
      selectedEvent ? { incidentId: selectedEvent.id } : { scenarioId: "indirect_prompt_injection" },
    );
    setBundle(nextBundle);
  }

  async function copyReport() {
    if (!report) {
      return;
    }
    await navigator.clipboard.writeText(report.content);
  }

  function downloadReport() {
    if (!report) {
      return;
    }
    const blob = new Blob([report.content], {
      type: report.format === "html" ? "text/html;charset=utf-8" : "text/markdown;charset=utf-8",
    });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = report.fileName;
    anchor.click();
    URL.revokeObjectURL(url);
  }

  function downloadBundle(format: "markdown" | "html") {
    if (!bundle) {
      return;
    }
    const content = format === "html" ? bundle.htmlReport : bundle.markdownReport;
    const blob = new Blob([content], {
      type: format === "html" ? "text/html;charset=utf-8" : "text/markdown;charset=utf-8",
    });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `prometheus-${bundle.incidentId}-audit-bundle.${format === "html" ? "html" : "md"}`;
    anchor.click();
    URL.revokeObjectURL(url);
  }

  function openEvidence(eventId: string, agentId: string) {
    setSelectedEventId(eventId);
    setSelectedNodeId(agentId);
    setEvidenceOpen(true);
  }

  async function restoreIncident(incident: IncidentSummary | AuditReportArchiveItem) {
    const detail = await loadIncident(incident.incidentId);
    if (!detail) {
      return;
    }
    setSelectedEventId(detail.event.id);
    setSelectedNodeId(detail.event.agentId);
    setEvidenceOpen(true);
    setReportOpen(true);
    setReport(await generateReport({ incidentId: detail.event.id }, report?.format ?? "markdown"));
  }

  async function replayLastGatewayDecision() {
    if (!snapshot.lastToolCall) {
      return;
    }
    await replayToolCall(snapshot.lastToolCall.requestId);
  }

  const showTribunal = Boolean(snapshot.activeTribunal);
  const relatedEvents =
    selectedNode?.relatedEventIds
      ?.map((eventId) => snapshot.events.find((event) => event.id === eventId))
      .filter((event): event is EventRecord => Boolean(event)) ?? [];

  return (
    <>
      <div
        className={`prometheus-shell${judgeMode ? " judge-mode" : ""}${presentationMode ? " presentation-mode" : ""}`}
      >
        <header className="hero-bar">
          <div className="brand-block">
            <SigilIcon />
            <div>
              <div className="brand-wordmark">PROMETHEUS</div>
              <div className="brand-tag">Pre-Crime Governance for Enterprise AI Agents</div>
            </div>
          </div>

          <div className="tenant-block">
            {tenantDescriptor ? <div className="tenant-detail">{tenantDescriptor}</div> : null}
            <div className="tenant-label">{tenantName}</div>
            <div className="tenant-meta">
              <span>PROMETHEUS v{snapshot.productVersion}</span>
              <span>{snapshot.connectionMode === "live" ? "Backend streaming" : "Local simulation"}</span>
              <span>{geminiStatus.headline}</span>
            </div>
          </div>

          <div className="hero-controls">
            <div className="hero-status-stack">
              <div className="live-indicator">
                <span className={`live-dot${geminiAvailable ? "" : " fallback"}`} />
                <span>{geminiStatus.headline}</span>
              </div>
              {integrationStatusWarning ? <div className="hero-status-note">{integrationStatusWarning}</div> : null}
              {!integrationStatusWarning && geminiStatus.error ? <div className="hero-status-note">{geminiStatus.error}</div> : null}
            </div>
            <div className="hero-actions">
              <button
                className={`toggle-pill${presentationMode ? " active" : ""}`}
                type="button"
                onClick={() => setPresentationMode((current) => !current)}
              >
                Presentation Mode
              </button>
              <button className={`toggle-pill${judgeMode ? " active" : ""}`} type="button" onClick={() => setJudgeMode((current) => !current)}>
                Judge Mode
              </button>
              <button className="btn-demo" type="button" onClick={() => startTransition(() => void requestBundle())}>
                Generate Audit Bundle
              </button>
              <button
                className={`btn-demo${snapshot.reportReady ? " highlighted" : ""}`}
                type="button"
                onClick={() => startTransition(() => void requestReport(report?.format ?? "markdown"))}
              >
                Generate Regulator Report
              </button>
            </div>
          </div>
        </header>

        {!presentationMode ? (
          <div className="sponsor-ribbon">
            <span>{snapshot.sponsorStatus}</span>
            <span className="divider" />
            <span>{lobsterTrapStatus.headline}</span>
            <span className="divider" />
            <span>Policy pack: {activePolicy.label}</span>
            <span className="divider" />
            <span>Audit trail: {auditTrailLabel}</span>
          </div>
        ) : null}

        {!presentationMode ? (
          <section className="compliance-row">
            {snapshot.complianceLabels.map((label) => (
              <span className="compliance-chip" key={label}>
                {label}
              </span>
            ))}
            <span className="compliance-chip muted">
              Demo remains fully operational even without external model credentials.
            </span>
            <span className="compliance-chip muted">
              Shortcuts: D demo | R drill | J judge | P presentation | G report
            </span>
          </section>
        ) : null}

        <section className={`kpi-row${presentationMode ? " presentation-focus" : ""}`}>
          {visibleKpis.map((card) => (
            <article className="kpi-card" key={card.id}>
              <div className="kpi-label">{card.label}</div>
              <div className="kpi-value">
                {card.value}
                {card.suffix ? <span>{card.suffix}</span> : null}
              </div>
              <div className="kpi-meta">{card.meta}</div>
            </article>
          ))}
          <article className="control-card">
            <div className="control-head">
              <div>
                <div className="kpi-label">Red team controls</div>
                <div className="control-stage">{snapshot.demoStage}</div>
              </div>
              <div className="control-badges">
                <span>{snapshot.demoRunning ? `${snapshot.countdownSeconds}s` : "Armed"}</span>
                <span>{snapshot.demoProgressPercent}%</span>
              </div>
            </div>
            <div className="control-actions">
              <button className="btn-redteam" type="button" onClick={() => startTransition(() => void runDrill())}>
                Red Team Drill
              </button>
              <button className="btn-demo" type="button" onClick={() => startTransition(() => void runDemo())}>
                Demo Mode 90s
              </button>
            </div>
            <div className="demo-progress">
              <div className="demo-progress-bar" style={{ width: `${snapshot.demoProgressPercent}%` }} />
            </div>
            <p className="control-copy">{snapshot.statusMessage}</p>
          </article>
        </section>

        {judgeMode || presentationMode ? (
          <section className="judge-story">
            <article className="story-card">
              <div className="eyebrow">Problem</div>
              <h3>{activeIncident?.declaredIntent ?? "Normal operations"}</h3>
              <p>{activeIncident?.businessImpact ?? "Fleet healthy and governed."}</p>
            </article>
            <article className="story-card">
              <div className="eyebrow">Attack</div>
              <h3>{selectedEvent?.detectedIntent ?? "None"}</h3>
              <p>{selectedEvent?.explanation ?? "No active incident."}</p>
            </article>
            <article className="story-card">
              <div className="eyebrow">Detection</div>
                <h3>{selectedEvent?.evidence.matchedPolicyRules?.join(", ") || "No matches"}</h3>
              <p>Lobster Trap-style DPI plus behavioral divergence show the gap between intent and action.</p>
            </article>
            <article className="story-card">
              <div className="eyebrow">Decision</div>
              <h3>{activeIncident?.decisionLabel ?? "Standby"}</h3>
              <p>{snapshot.activeTribunal?.explanation ?? "Tribunal ready for the next incident."}</p>
            </article>
            <article className="story-card">
              <div className="eyebrow">Audit trail</div>
              <h3>{snapshot.reportReady ? "Report ready" : "Narrative building"}</h3>
              <p>Historian packages regulator-ready evidence, timeline, and sponsor visibility.</p>
            </article>
            <article className="story-card">
              <div className="eyebrow">Enterprise value</div>
              <h3>{selectedEvent?.impact.enterpriseValue ?? "Risk reduction visible"}</h3>
              <p>Prometheus turns AI agent behavior into a deployable security control plane for CISOs and compliance teams.</p>
            </article>
          </section>
        ) : null}

        <main className="content-grid">
          <div className="content-main">
            <section className={`panel panel-command${presentationMode ? " presentation-incident" : ""}`}>
              <div className="panel-head">
                <div>
                  <div className="eyebrow">Incident Command Center</div>
                  <h2>Active enterprise incident</h2>
                </div>
                <div className={`decision-banner ${severityClass(activeIncident?.severity ?? "medium")}`}>
                  {activeIncident?.decisionLabel ?? "No active incident"}
                </div>
              </div>
              {judgeMode ? <JudgeCaption>Problem, attack, detection, decision, and business consequence in one view.</JudgeCaption> : null}
              <div className="command-grid">
                <div className="command-item">
                  <span>Incident ID</span>
                  <strong>{activeIncident?.incidentId ?? "None"}</strong>
                </div>
                <div className="command-item">
                  <span>Severity</span>
                  <strong>{titleCase(activeIncident?.severity ?? "low")}</strong>
                </div>
                <div className="command-item">
                  <span>Affected agent</span>
                  <strong>{activeIncident?.affectedAgent ?? "Fleet"}</strong>
                </div>
                <div className="command-item">
                  <span>Declared intent</span>
                  <strong>{activeIncident?.declaredIntent ?? "Normal operations"}</strong>
                </div>
                <div className="command-item">
                  <span>Detected intent</span>
                  <strong>{activeIncident?.detectedIntent ?? "None"}</strong>
                </div>
                <div className="command-item">
                  <span>Predicted action</span>
                  <strong>{activeIncident?.predictedAction ?? "N/A"}</strong>
                </div>
                <div className="command-item">
                  <span>Observed action</span>
                  <strong>{activeIncident?.observedAction ?? "N/A"}</strong>
                </div>
                <div className="command-item">
                  <span>Policy matched</span>
                  <strong>{activeIncident?.policyMatched.join(", ") || "none"}</strong>
                </div>
                <div className="command-item">
                  <span>Final decision</span>
                  <strong>{activeIncident?.finalDecision ?? "ALLOW"}</strong>
                </div>
                <div className="command-item span-2">
                  <span>Business impact</span>
                  <strong>{activeIncident?.businessImpact ?? "No material impact."}</strong>
                </div>
                <div className="command-item span-2">
                  <span>Regulatory impact</span>
                  <strong>{activeIncident?.regulatoryImpact ?? "No current regulatory exposure."}</strong>
                </div>
              </div>
            </section>

            {!presentationMode ? (
            <section className="panel panel-side-by-side">
              <div className="stack-panel">
                <div className="panel-head compact">
                  <div>
                    <div className="eyebrow">Policy pack switcher</div>
                    <h3>{activePolicy.label}</h3>
                  </div>
                  <div className="policy-thresholds">
                    <span>Block {activePolicy.thresholdBlock.toFixed(2)}</span>
                    <span>Quarantine {activePolicy.thresholdQuarantine.toFixed(2)}</span>
                  </div>
                </div>
                {judgeMode ? <JudgeCaption>Shows how the same platform adapts to different compliance regimes.</JudgeCaption> : null}
                <div className="policy-pack-grid">
                  {snapshot.policyPacks.map((pack) => (
                    <button
                      key={pack.id}
                      className={`policy-pack-card${pack.id === snapshot.activePolicyPack ? " active" : ""}`}
                      type="button"
                      onClick={() => startTransition(() => void selectPolicyPack(pack.id))}
                    >
                      <span className="policy-pack-label">{pack.label}</span>
                      <span className="policy-pack-summary">{pack.summary}</span>
                    </button>
                  ))}
                </div>
                <div className="policy-label-row">
                  <span>Allow: {activePolicy.decisionLabels.allow}</span>
                  <span>Block: {activePolicy.decisionLabels.block}</span>
                  <span>Quarantine: {activePolicy.decisionLabels.quarantine}</span>
                </div>
              </div>

              <div className="stack-panel">
                <div className="panel-head compact integration-panel-head">
                  <div>
                    <div className="eyebrow">Integration status</div>
                    <h3>Operational dependencies</h3>
                  </div>
                  <button
                    className="btn-ghost"
                    type="button"
                    onClick={() => startTransition(() => void refreshIntegrationStatus())}
                  >
                    Refresh status
                  </button>
                </div>
                {judgeMode ? <JudgeCaption>Judges can see what is connected live and what still degrades safely into simulation.</JudgeCaption> : null}
                <div className="integration-list">
                  <div className="integration-row">
                    <span>Veea Lobster Trap</span>
                    <strong>{lobsterTrapStatus.headline}</strong>
                  </div>
                  <div className="integration-row">
                    <span>Gemini</span>
                    <strong>{geminiStatus.headline}</strong>
                  </div>
                  <div className="integration-row">
                    <span>Binary</span>
                    <strong>
                      {resolvedIntegrationStatus
                        ? resolvedIntegrationStatus.lobsterTrapBinFound
                          ? "Found"
                          : "Missing"
                        : "Unknown"}
                    </strong>
                  </div>
                  <div className="integration-row">
                    <span>Policy</span>
                    <strong>
                      {resolvedIntegrationStatus
                        ? resolvedIntegrationStatus.policyFileFound
                          ? "Found"
                          : "Missing"
                        : "Unknown"}
                    </strong>
                  </div>
                  <div className="integration-row">
                    <span>Mode</span>
                    <strong>{resolvedIntegrationStatus?.lobsterTrapMode ?? "status_unavailable"}</strong>
                  </div>
                  <div className="integration-row">
                    <span>Policy pack</span>
                    <strong>{activePolicy.label}</strong>
                  </div>
                  <div className="integration-row">
                    <span>Audit trail</span>
                    <strong>{auditTrailLabel}</strong>
                  </div>
                  <div className="integration-row">
                    <span>Rules loaded</span>
                    <strong>{resolvedIntegrationStatus?.policyRuleCount ?? "Unknown"}</strong>
                  </div>
                  <div className="integration-row">
                    <span>SQLite archive</span>
                    <strong>
                      {resolvedIntegrationStatus
                        ? resolvedIntegrationStatus.databaseAvailable
                          ? "Online"
                          : "Fallback mode"
                        : "Unknown"}
                    </strong>
                  </div>
                </div>
                {integrationStatusWarning ? <p className="integration-note">{integrationStatusWarning}</p> : null}
                {!integrationStatusWarning && geminiStatus.error ? <p className="integration-note">{geminiStatus.error}</p> : null}
                {!integrationStatusWarning && lobsterTrapStatus.note ? <p className="integration-note">{lobsterTrapStatus.note}</p> : null}
                <div className="integration-models">
                  <span>Binary path: {resolvedIntegrationStatus?.lobsterTrapBinPath || "not configured"}</span>
                  <span>Policy path: {resolvedIntegrationStatus?.lobsterTrapPolicyPath || "not configured"}</span>
                  <span>Reasoning: {resolvedIntegrationStatus?.geminiReasoningModel || "unknown"}</span>
                  <span>Fast: {resolvedIntegrationStatus?.geminiFastModel || "unknown"}</span>
                  <span>Lite: {resolvedIntegrationStatus?.geminiLiteModel || "unknown"}</span>
                </div>
                {process.env.NODE_ENV !== "production" ? (
                  <details className="integration-debug">
                    <summary>Debug status</summary>
                    <div className="integration-debug-grid">
                      <span>Frontend origin: {frontendOrigin}</span>
                      <span>NEXT_PUBLIC_API_URL: {apiBaseUrl}</span>
                      <span>Integration fetch: {integrationStatusFetchState}</span>
                      <span>Integration error: {integrationStatusError ?? "none"}</span>
                      <span>Snapshot error: {snapshotError ?? "none"}</span>
                    </div>
                  </details>
                ) : null}
              </div>
            </section>
            ) : null}

            {!presentationMode ? (
            <section className="panel panel-side-by-side">
              <div className="stack-panel">
                <div className="panel-head compact integration-panel-head">
                  <div>
                    <div className="eyebrow">Agent Tool Gateway</div>
                    <h3>Execution path enforcement</h3>
                  </div>
                  {snapshot.lastToolCall ? (
                    <button
                      className="btn-ghost"
                      type="button"
                      onClick={() => startTransition(() => void replayLastGatewayDecision())}
                    >
                      Replay under current policy
                    </button>
                  ) : null}
                </div>
                {snapshot.lastToolCall ? (
                  <>
                    <div className="integration-list">
                      <div className="integration-row">
                        <span>Status</span>
                        <strong>{snapshot.lastToolCall.decision === "HUMAN_REVIEW" ? "HUMAN REVIEW REQUIRED" : snapshot.lastToolCall.decision === "BLOCK" ? "BLOCKED BEFORE EXECUTION" : snapshot.lastToolCall.decision === "QUARANTINE" ? "QUARANTINED" : "EXECUTED"}</strong>
                      </div>
                      <div className="integration-row">
                        <span>Agent</span>
                        <strong>{snapshot.lastToolCall.agentId}</strong>
                      </div>
                      <div className="integration-row">
                        <span>Tool requested</span>
                        <strong>{snapshot.lastToolCall.toolName}</strong>
                      </div>
                      <div className="integration-row">
                        <span>Declared intent</span>
                        <strong>{snapshot.lastToolCall.declaredIntent}</strong>
                      </div>
                      <div className="integration-row">
                        <span>Detected intent</span>
                        <strong>{snapshot.lastToolCall.detectedIntent}</strong>
                      </div>
                      <div className="integration-row">
                        <span>Permission status</span>
                        <strong>{titleCase(snapshot.lastToolCall.permissionEvaluation.permissionState)}</strong>
                      </div>
                      <div className="integration-row">
                        <span>Gemini prediction</span>
                        <strong>{snapshot.lastToolCall.predictedAction}</strong>
                      </div>
                      <div className="integration-row">
                        <span>Tribunal</span>
                        <strong>{snapshot.lastToolCall.tribunalVotes.length > 0 ? snapshot.lastToolCall.decision : "Not required"}</strong>
                      </div>
                      <div className="integration-row">
                        <span>Tool executed</span>
                        <strong>{snapshot.lastToolCall.toolExecuted ? "Yes" : "No"}</strong>
                      </div>
                    </div>
                    <div className="drawer-block">
                      <div className="drawer-label">Reason</div>
                      <p>{snapshot.lastToolCall.reason}</p>
                    </div>
                    {snapshot.lastToolCall.sideEffectPrevented ? (
                      <div className="drawer-block">
                        <div className="drawer-label">Side effect prevented</div>
                        <p>{snapshot.lastToolCall.sideEffectPrevented}</p>
                      </div>
                    ) : null}
                  </>
                ) : (
                  <p className="integration-note">No sandbox tool call has been intercepted yet.</p>
                )}
              </div>

              <div className="stack-panel">
                <div className="panel-head compact">
                  <div>
                    <div className="eyebrow">Agent Permission Matrix</div>
                    <h3>Least-privilege enforcement</h3>
                  </div>
                </div>
                <div className="permission-matrix-shell">
                  <div
                    className="permission-matrix"
                    style={{
                      gridTemplateColumns: `minmax(180px, 1.2fr) repeat(${Math.max(snapshot.permissionMatrix.tools.length, 1)}, minmax(130px, 1fr))`,
                    }}
                  >
                    <div className="permission-cell permission-head">Agent</div>
                    {snapshot.permissionMatrix.tools.map((toolName) => (
                      <div key={toolName} className="permission-cell permission-head">
                        {toolName}
                      </div>
                    ))}
                    {snapshot.permissionMatrix.rows.map((row) => (
                      <Fragment key={row.agentId}>
                        <div className="permission-cell permission-agent">{row.agentName}</div>
                        {snapshot.permissionMatrix.tools.map((toolName) => {
                          const state = row.cells[toolName] ?? "denied";
                          return (
                            <div key={`${row.agentId}-${toolName}`} className={`permission-cell permission-${state}`}>
                              {state === "allowed" ? "Allowed" : state === "human_review" ? "Human Review" : state === "quarantine" ? "Quarantine" : "Denied"}
                            </div>
                          );
                        })}
                      </Fragment>
                    ))}
                  </div>
                </div>
              </div>
            </section>
            ) : null}

            {!presentationMode ? (
            <section className="panel">
              <div className="panel-head">
                <div>
                  <div className="eyebrow">Live agent grid</div>
                  <h2>Governed production agents</h2>
                </div>
                <div className="panel-meta">{snapshot.agents.length} agents in scope</div>
              </div>
              {judgeMode ? <JudgeCaption>Each agent carries a trust score, operating lane, and policy exposure footprint.</JudgeCaption> : null}
              <div className="agent-grid">
                {snapshot.agents.map((agent) => (
                  <article
                    key={agent.id}
                    className={`agent-card ${statusClass(agent.status)}${selectedNodeId === agent.id ? " selected" : ""}`}
                    onClick={() => setSelectedNodeId(agent.id)}
                  >
                    <div className="agent-top">
                      <div>
                        <div className="agent-name">{agent.name}</div>
                        <div className="agent-meta">{agent.id} | {agent.role}</div>
                      </div>
                      <span className="status-badge">{agent.status}</span>
                    </div>
                    <div className="agent-mid">
                      <div>
                        <div className="trust-score">{agent.trustScore}</div>
                        <div className={`trust-delta ${agent.trustDelta > 0 ? "up" : agent.trustDelta < 0 ? "down" : "flat"}`}>
                          {formatDelta(agent.trustDelta)}
                        </div>
                      </div>
                      <div className={`spark-shell ${statusClass(agent.status)}`}>
                        <Sparkline points={agent.sparkline} />
                      </div>
                    </div>
                    <div className="agent-baseline">{agent.baseline}</div>
                    <div className="agent-foot">
                      <span>{agent.accessLevel}</span>
                      <span>{agent.lastAction}</span>
                    </div>
                  </article>
                ))}
              </div>
            </section>
            ) : null}

            {!presentationMode ? (
            <section className="panel">
              <div className="panel-head">
                <div>
                  <div className="eyebrow">Human review queue</div>
                  <h2>Pending governance decisions</h2>
                </div>
                <div className="panel-meta">{snapshot.reviewQueue.length} items awaiting review</div>
              </div>
              {judgeMode ? <JudgeCaption>This is the human override layer compliance teams expect in a real deployment.</JudgeCaption> : null}
              <div className="queue-list">
                {snapshot.reviewQueue.map((item) => (
                  <article className="queue-card" key={item.eventId}>
                    <div className="queue-top">
                      <div>
                        <div className="queue-title">{item.incidentId}</div>
                        <div className="queue-meta">
                          {item.agentId} | {item.businessOwner}
                        </div>
                      </div>
                      <span className={`queue-status ${item.status}`}>{item.status}</span>
                    </div>
                    <div className="queue-detail-row">
                      <span>Requested action: {item.requestedAction}</span>
                      <span>Policy: {item.policyPack.toUpperCase()}</span>
                      <span>Severity: {item.severity}</span>
                    </div>
                    <div className="queue-actions">
                      {[
                        ["Approve", "approved"],
                        ["Deny", "denied"],
                        ["Quarantine", "quarantined"],
                        ["Escalate", "escalated"],
                      ].map(([label, action]) => {
                        const key = `${item.eventId}:${action}`;
                        return (
                          <button
                            key={action}
                            className="queue-button"
                            type="button"
                            onClick={() => startTransition(() => void handleReviewAction(item, action as "approved" | "denied" | "quarantined" | "escalated"))}
                            disabled={reviewBusyKey === key}
                          >
                            {reviewBusyKey === key ? "Working..." : label}
                          </button>
                        );
                      })}
                    </div>
                  </article>
                ))}
              </div>
            </section>
            ) : null}

            <section className="panel">
              <div className="panel-head">
                <div>
                  <div className="eyebrow">Enterprise metrics</div>
                  <h2>CISO and compliance outcomes</h2>
                </div>
              </div>
              <JudgeCaption>
                Before Prometheus: agent logs are fragmented across tools. After Prometheus: decisions, evidence, and audit trail are unified.
              </JudgeCaption>
              <div className="enterprise-grid">
                {visibleEnterpriseMetrics.map((metric) => (
                  <article className={`enterprise-card ${metricEmphasisClass(metric.emphasis)}`} key={metric.id}>
                    <div className="kpi-label">{metric.label}</div>
                    <div className="enterprise-value">{metric.value}</div>
                    <div className="enterprise-trend">{metric.trend}</div>
                  </article>
                ))}
              </div>
            </section>

            {!presentationMode ? (
            <section className="panel">
              <div className="panel-head">
                <div>
                  <div className="eyebrow">Knowledge graph</div>
                  <h2>Operational dependency map</h2>
                </div>
                <div className="panel-meta">
                  {snapshot.knowledgeGraph.nodes.length} nodes | {snapshot.knowledgeGraph.edges.length} edges
                </div>
              </div>
              {judgeMode ? <JudgeCaption>Click any node to show its trust score, related events, access level, and policy exposure.</JudgeCaption> : null}
              <div className="graph-layout">
                <div className="graph-canvas">
                  <KnowledgeGraphPanel
                    graph={snapshot.knowledgeGraph}
                    selectedNodeId={selectedNodeId}
                    onSelectNode={setSelectedNodeId}
                  />
                </div>
                <aside className="node-panel">
                  <div className="node-head">
                    <div className="eyebrow">Node detail</div>
                    <h3>{selectedNode?.label ?? "Select a node"}</h3>
                  </div>
                  <div className="node-detail-list">
                    <div>
                      <span>Node type</span>
                      <strong>{selectedNode ? titleCase(selectedNode.type) : "N/A"}</strong>
                    </div>
                    <div>
                      <span>Trust score</span>
                      <strong>{selectedNode?.trustScore ?? "N/A"}</strong>
                    </div>
                    <div>
                      <span>Access level</span>
                      <strong>{selectedNode?.accessLevel ?? "N/A"}</strong>
                    </div>
                    <div>
                      <span>Policy exposure</span>
                      <strong>{selectedNode?.policyExposure?.join(", ") ?? "N/A"}</strong>
                    </div>
                  </div>
                  <div className="drawer-label">Related events</div>
                  <div className="related-events">
                    {relatedEvents.length > 0 ? (
                      relatedEvents.map((event) => (
                        <button
                          key={event.id}
                          className="related-event"
                          type="button"
                          onClick={() => openEvidence(event.id, event.agentId)}
                        >
                          <span>{event.title}</span>
                          <strong>{event.decisionLabel}</strong>
                        </button>
                      ))
                    ) : (
                      <p>No related events for this node.</p>
                    )}
                  </div>
                </aside>
              </div>
            </section>
            ) : null}
          </div>

          <aside className="content-rail">
            {presentationMode ? (
              <section className="panel presentation-focus-panel">
                <div className="panel-head compact">
                  <div>
                    <div className="eyebrow">Tribunal / Evidence</div>
                    <h3>{snapshot.activeTribunal?.consensus ?? activeIncident?.decisionLabel ?? "Standby"}</h3>
                  </div>
                </div>
                <div className="related-events">
                  <div className="related-event">
                    <span>Matched rules</span>
                      <strong>{selectedEvent?.evidence.matchedPolicyRules?.join(", ") || "none"}</strong>
                  </div>
                  <div className="related-event">
                    <span>Compliance concern</span>
                    <strong>{activeIncident?.complianceConcern ?? "Awaiting incident"}</strong>
                  </div>
                  <div className="related-event">
                    <span>Gemini status</span>
                    <strong>{geminiStatus.headline}</strong>
                  </div>
                  <div className="related-event">
                    <span>Lobster Trap</span>
                    <strong>{lobsterTrapStatus.badge}</strong>
                  </div>
                </div>
                {integrationStatusWarning ? <p className="integration-note">{integrationStatusWarning}</p> : null}
                {!integrationStatusWarning && geminiStatus.error ? <p className="integration-note">{geminiStatus.error}</p> : null}
                {!integrationStatusWarning && lobsterTrapStatus.note ? <p className="integration-note">{lobsterTrapStatus.note}</p> : null}
              </section>
            ) : null}

            <section className="panel rail-panel">
              <div className="panel-head">
                <div>
                  <div className="eyebrow">Prediction stream</div>
                  <h2>
                    <StreamIcon /> Divergence timeline
                  </h2>
                </div>
                <div className="panel-meta">
                  {geminiStatus.streamLabel}
                </div>
              </div>
              {judgeMode ? <JudgeCaption>Click any event to open the evidence drawer and walk judges from prompt to verdict.</JudgeCaption> : null}
              <div className="stream-list">
                {snapshot.events.map((event) => (
                  <button
                    key={event.id}
                    className={`stream-card ${severityClass(event.severity)}${selectedEventId === event.id ? " selected" : ""}`}
                    type="button"
                    onClick={() => openEvidence(event.id, event.agentId)}
                  >
                    <div className="stream-top">
                      <span>{event.agentId}</span>
                      <span>{formatTime(event.timestamp)}</span>
                    </div>
                    <div className="stream-title">{event.title}</div>
                    <div className="stream-actions">
                      <span>Predicted: {event.predictedAction}</span>
                      <span>Observed: {event.observedAction}</span>
                    </div>
                    <div className="stream-flags">
                      {event.policySignals.map((signal) => (
                        <span key={`${event.id}-${signal.id}`} className={`flag-chip ${severityClass(signal.severity)}`}>
                          {signal.label}
                        </span>
                      ))}
                    </div>
                    <div className="stream-foot">
                      <div>
                        <div className="stream-consensus">{event.tribunalConsensus}</div>
                        <div className="stream-impact">{event.impact.department}</div>
                      </div>
                      <DivergenceRing value={event.divergenceScore} severity={event.severity} />
                    </div>
                  </button>
                ))}
              </div>
            </section>

            {presentationMode ? (
              <section className="panel presentation-focus-panel">
                <div className="panel-head compact">
                  <div>
                    <div className="eyebrow">Audit Bundle</div>
                    <h3>{bundle ? "Historian sealed" : snapshot.reportReady ? "Ready to generate" : "Narrative building"}</h3>
                  </div>
                </div>
                <div className="related-events">
                  <div className="related-event">
                    <span>Report status</span>
                    <strong>{snapshot.reportReady ? "Ready" : "Standby"}</strong>
                  </div>
                  <div className="related-event">
                    <span>Bundle hash</span>
                    <strong>{bundle?.auditHash ?? "Generate Audit Bundle"}</strong>
                  </div>
                </div>
                <div className="queue-actions">
                  <button className="btn-demo" type="button" onClick={() => startTransition(() => void requestBundle())}>
                    Generate Audit Bundle
                  </button>
                  <button
                    className={`btn-demo${snapshot.reportReady ? " highlighted" : ""}`}
                    type="button"
                    onClick={() => startTransition(() => void requestReport(report?.format ?? "markdown"))}
                  >
                    Generate Report
                  </button>
                </div>
              </section>
            ) : null}

            {!presentationMode ? (
              <section className="panel">
                <div className="panel-head compact">
                  <div>
                    <div className="eyebrow">Incident history</div>
                    <h3>Recent incidents</h3>
                  </div>
                  <div className="panel-meta">{incidents.length} archived</div>
                </div>
                <div className="related-events">
                  {incidents.slice(0, 6).map((incident) => (
                    <button
                      key={incident.incidentId}
                      className="related-event"
                      type="button"
                      onClick={() => startTransition(() => void restoreIncident(incident))}
                    >
                      <span>{incident.title}</span>
                      <strong>{incident.decisionLabel}</strong>
                    </button>
                  ))}
                </div>
              </section>
            ) : null}

            {!presentationMode ? (
              <section className="panel">
                <div className="panel-head compact">
                  <div>
                    <div className="eyebrow">Report archive</div>
                    <h3>Historian bundles</h3>
                  </div>
                  <div className="panel-meta">{reportArchive.length} reports</div>
                </div>
                <div className="related-events">
                  {reportArchive.slice(0, 6).map((entry) => (
                    <button
                      key={`${entry.incidentId}-${entry.generatedAt}-${entry.format}`}
                      className="related-event"
                      type="button"
                      onClick={() => startTransition(() => void restoreIncident(entry))}
                    >
                      <span>{entry.title}</span>
                      <strong>{entry.format}</strong>
                    </button>
                  ))}
                </div>
              </section>
            ) : null}
          </aside>
        </main>

        <footer className="status-bar">
          <span>PROMETHEUS v{snapshot.productVersion}</span>
          <span className="divider" />
          <span>{snapshot.connectionMode === "live" ? "Backend streaming" : "Local simulation"}</span>
          <span className="divider" />
          <span>Tribunal {snapshot.activeTribunal ? "active" : "standby"}</span>
          <span className="divider" />
          <span>Last updated {formatTime(snapshot.lastUpdated)}</span>
        </footer>
      </div>

      {evidenceOpen ? <EvidenceDrawer event={selectedEvent} onClose={() => setEvidenceOpen(false)} /> : null}
      {showTribunal && snapshot.activeTribunal ? (
        <TribunalModal tribunal={snapshot.activeTribunal} onClose={clearTribunal} />
      ) : null}
      {reportOpen ? (
        <ReportModal
          report={report}
          loading={reportLoading}
          onClose={() => setReportOpen(false)}
          onCopy={() => void copyReport()}
          onDownload={downloadReport}
          onFormatChange={(format) => startTransition(() => void requestReport(format))}
        />
      ) : null}
      {bundleOpen ? (
        <AuditBundleModal
          bundle={bundle}
          onClose={() => setBundleOpen(false)}
          onCopyHash={() => void navigator.clipboard.writeText(bundle?.auditHash ?? "")}
          onDownload={downloadBundle}
        />
      ) : null}
    </>
  );
}
