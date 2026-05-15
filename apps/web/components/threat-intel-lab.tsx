"use client";

import type {
  ThreatIntelInput,
  ThreatIntelRunResult,
  ThreatIntelRunSummary,
  ToolCallDecisionRecord,
} from "@prometheus/shared";
import { startTransition, useEffect, useMemo, useState } from "react";

import { useDashboardRuntime } from "../hooks/use-dashboard-runtime";
import {
  analyzeThreatIntel,
  fetchThreatIntelRun,
  fetchThreatIntelRuns,
} from "../lib/api";
import {
  getGeminiStatusCopy,
  getLobsterTrapStatusCopy,
  splitTenantLabel,
} from "../lib/integration-status";

const DEFAULT_REPORT = `A safe public report says attackers used AI to accelerate vulnerability research. It raises possible exploit-generation intent, possible authentication-bypass testing, and mass exploitation planning pressure. Enterprise controls should block exploit generation, quarantine identity-bypass testing, and require human review for scanners.`;

const SAFE_BY_DESIGN_POINTS = [
  "No exploit code generated",
  "No live targets scanned",
  "No payloads created",
  "No offensive execution permitted",
  "Synthetic tool calls only",
  "Dangerous tools are blocked before execution",
];

const MITIGATION_COVERAGE = [
  {
    key: "research",
    label: "AI-assisted vulnerability research",
    keywords: ["vulnerability research", "vuln.research", "research"],
    tools: ["vuln.research"],
  },
  {
    key: "exploit-generation",
    label: "exploit-generation intent",
    keywords: ["exploit", "exploit-development"],
    tools: ["exploit.generate", "exploit.execute"],
  },
  {
    key: "auth-bypass",
    label: "authentication bypass testing",
    keywords: ["auth", "bypass", "identity-bypass"],
    tools: ["auth.bypass_test"],
  },
  {
    key: "mass-exploitation",
    label: "mass exploitation planning",
    keywords: ["mass exploitation", "scale", "automation"],
    tools: ["exploit.execute", "scanner.run"],
  },
  {
    key: "scanner-activity",
    label: "scanner activity",
    keywords: ["scanner", "scan"],
    tools: ["scanner.run"],
  },
  {
    key: "external-exfiltration",
    label: "external exfiltration risk",
    keywords: ["exfiltration", "external", "egress"],
    tools: ["email.send_external", "finance.export_external"],
  },
  {
    key: "unsafe-downstream-execution",
    label: "unsafe downstream execution",
    keywords: ["downstream", "execution", "tool call"],
    tools: ["exploit.generate", "exploit.execute", "auth.bypass_test", "scanner.run"],
  },
];

function defaultInput(policyPack: string): ThreatIntelInput {
  return {
    title: "AI-assisted zero-day style activity",
    source: "Public threat reporting",
    reportText: DEFAULT_REPORT,
    policyPack,
    industry: "financial services",
    createScenario: true,
    runSimulation: true,
  };
}

function formatTimestamp(value: string | null | undefined): string {
  if (!value) {
    return "Not available";
  }
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return value;
  }
  return `${parsed.toISOString().replace("T", " ").slice(0, 16)} UTC`;
}

function asBooleanLabel(value: boolean | null | undefined): string {
  if (value === null || value === undefined) {
    return "not_available";
  }
  return value ? "true" : "false";
}

function policyYamlValue(value: string): string {
  return `"${value.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

function buildPolicyPatchYaml(result: ThreatIntelRunResult | null): string {
  if (!result || result.policyPatch.length === 0) {
    return "rules: []";
  }
  const lines = ["rules:"];
  for (const rule of result.policyPatch) {
    lines.push(`  - name: ${rule.ruleName}`);
    lines.push(`    action: ${rule.action}`);
    lines.push(`    condition: ${policyYamlValue(rule.condition)}`);
    lines.push(`    reason: ${policyYamlValue(rule.reason)}`);
  }
  return lines.join("\n");
}

function proofStatusLabel(result: ThreatIntelRunResult | null): string | null {
  if (!result?.gatewayDecision) {
    return null;
  }
  if (result.blockedBeforeExecution || (result.gatewayDecision.decision === "BLOCK" && !result.gatewayDecision.toolExecuted)) {
    return "BLOCKED BEFORE EXECUTION";
  }
  if (result.gatewayDecision.decision === "QUARANTINE") {
    return "QUARANTINED";
  }
  if (result.gatewayDecision.decision === "HUMAN_REVIEW") {
    return "HUMAN REVIEW";
  }
  return "ALLOWED";
}

function proofStatusTone(status: string | null): string {
  switch (status) {
    case "BLOCKED BEFORE EXECUTION":
      return "proof-blocked";
    case "QUARANTINED":
      return "proof-quarantined";
    case "HUMAN REVIEW":
      return "proof-review";
    case "ALLOWED":
      return "proof-allowed";
    default:
      return "proof-muted";
  }
}

function lobsterTrapSourceLabel(decision: ToolCallDecisionRecord | null): string {
  if (!decision) {
    return "Not available";
  }
  if (decision.dpiSource === "veea_lobstertrap_cli") {
    return "Veea Lobster Trap CLI";
  }
  return "Deterministic fallback";
}

function buildTribunalSummary(decision: ToolCallDecisionRecord | null): string {
  if (!decision || decision.tribunalVotes.length === 0) {
    return "Tribunal was not required for this decision.";
  }
  return decision.tribunalVotes.map((vote) => `${vote.judge}: ${vote.vote}`).join(" | ");
}

function includesKeyword(haystack: string[], keywords: string[]): boolean {
  const normalized = haystack.join(" ").toLowerCase();
  return keywords.some((keyword) => normalized.includes(keyword.toLowerCase()));
}

function downloadTextFile(fileName: string, content: string, mimeType: string): void {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = fileName;
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

async function copyTextToClipboard(text: string): Promise<void> {
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(text);
    return;
  }
  const helper = document.createElement("textarea");
  helper.value = text;
  helper.setAttribute("readonly", "true");
  helper.style.position = "fixed";
  helper.style.opacity = "0";
  document.body.append(helper);
  helper.select();
  document.execCommand("copy");
  helper.remove();
}

export function ThreatIntelLab({ apiBaseUrl }: { apiBaseUrl: string }) {
  const { snapshot } = useDashboardRuntime(apiBaseUrl);
  const [input, setInput] = useState<ThreatIntelInput>(() => defaultInput("soc2"));
  const [result, setResult] = useState<ThreatIntelRunResult | null>(null);
  const [runs, setRuns] = useState<ThreatIntelRunSummary[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [actionMessage, setActionMessage] = useState<string | null>(null);
  const [selectedRunId, setSelectedRunId] = useState<string | null>(null);
  const [restoringRunId, setRestoringRunId] = useState<string | null>(null);

  const geminiStatus = getGeminiStatusCopy(snapshot.integrationStatus);
  const lobsterTrapStatus = getLobsterTrapStatusCopy(snapshot.integrationStatus);
  const { tenantName, tenantDescriptor } = splitTenantLabel(snapshot.tenantLabel);

  useEffect(() => {
    setInput((current) => ({
      ...current,
      policyPack: current.policyPack || snapshot.activePolicyPack,
    }));
  }, [snapshot.activePolicyPack]);

  useEffect(() => {
    let active = true;
    void fetchThreatIntelRuns(apiBaseUrl)
      .then((nextRuns) => {
        if (active) {
          setRuns(nextRuns);
        }
      })
      .catch(() => {
        if (active) {
          setRuns([]);
        }
      });
    return () => {
      active = false;
    };
  }, [apiBaseUrl, result?.runId]);

  async function submit(runSimulation: boolean) {
    setBusy(true);
    setError(null);
    setActionMessage(null);
    try {
      const nextResult = await analyzeThreatIntel(apiBaseUrl, {
        ...input,
        createScenario: true,
        runSimulation,
      });
      setResult(nextResult);
      setSelectedRunId(nextResult.runId);
    } catch (submitError) {
      setError(submitError instanceof Error ? submitError.message : "Threat intel analysis failed.");
    } finally {
      setBusy(false);
    }
  }

  async function restoreRun(runId: string) {
    setRestoringRunId(runId);
    setError(null);
    setActionMessage(null);
    try {
      const restored = await fetchThreatIntelRun(apiBaseUrl, runId);
      setResult(restored);
      setSelectedRunId(runId);
    } catch (restoreError) {
      setError(restoreError instanceof Error ? restoreError.message : "Unable to restore the selected run.");
    } finally {
      setRestoringRunId(null);
    }
  }

  const policyPatchYaml = useMemo(() => buildPolicyPatchYaml(result), [result]);
  const scenarioJson = useMemo(
    () => (result?.generatedScenario ? JSON.stringify(result.generatedScenario, null, 2) : ""),
    [result],
  );
  const gatewayDecision = result?.gatewayDecision ?? null;
  const proofLabel = useMemo(() => proofStatusLabel(result), [result]);
  const proofTone = proofStatusTone(proofLabel);
  const incidentId = result?.auditBundle?.incidentId ?? gatewayDecision?.sourceEventId ?? null;
  const auditHash = result?.auditBundle?.auditHash ?? gatewayDecision?.auditHash ?? null;
  const geminiMode = snapshot.integrationStatus.geminiMode === "connected" ? "connected" : "fallback";
  const fallbackUsed =
    gatewayDecision !== null &&
    (gatewayDecision.dpiMode !== "live_cli" || gatewayDecision.dpiSource !== "veea_lobstertrap_cli");
  const rawEvidencePreview =
    gatewayDecision?.rawLobstertrapOutputPreview ??
    gatewayDecision?.rawLobstertrapOutput ??
    "No raw Lobster Trap preview was returned for this run.";
  const tribunalSummary = buildTribunalSummary(gatewayDecision);

  const mitigationRows = useMemo(() => {
    if (!result) {
      return [];
    }
    const extractionParts = [
      result.extraction.threatSummary,
      result.extraction.attackerGoal,
      result.extraction.aiMisusePattern,
      ...result.extraction.suspectedTactics,
      ...result.extraction.riskyAgentBehaviors,
      ...result.extraction.dangerousToolCalls,
    ];

    return MITIGATION_COVERAGE.map((item) => {
      const matchedRule = result.policyPatch.find((rule) =>
        includesKeyword([rule.ruleName, rule.condition, rule.reason], item.keywords),
      );
      const matchedPermission = result.extraction.recommendedPermissionChanges.find((change) =>
        item.tools.includes(change.toolName) || includesKeyword([change.toolName, change.reason], item.keywords),
      );
      const covered =
        includesKeyword(extractionParts, item.keywords) ||
        matchedRule !== undefined ||
        matchedPermission !== undefined;
      const exercisedTool = result.generatedScenario?.attemptedTool ?? null;
      const exercisedDecision =
        exercisedTool && (item.tools.includes(exercisedTool) || includesKeyword([exercisedTool], item.keywords))
          ? proofLabel ?? gatewayDecision?.decision ?? "Not available"
          : "Not exercised in this simulation";

      return {
        key: item.key,
        label: item.label,
        covered,
        generatedRule: matchedRule ? `${matchedRule.ruleName} · ${matchedRule.action}` : "No specific generated rule",
        gatewayDecision: exercisedDecision,
        permissionControl: matchedPermission
          ? `${matchedPermission.toolName} · ${matchedPermission.recommendedState}`
          : "No specific permission change",
      };
    });
  }, [gatewayDecision?.decision, proofLabel, result]);

  async function handleCopyYaml() {
    if (!result) {
      return;
    }
    try {
      await copyTextToClipboard(policyPatchYaml);
      setActionMessage("Policy patch YAML copied.");
    } catch {
      setActionMessage("Unable to copy the policy patch from this browser context.");
    }
  }

  async function handleCopyScenario() {
    if (!result?.generatedScenario) {
      return;
    }
    try {
      await copyTextToClipboard(scenarioJson);
      setActionMessage("Scenario JSON copied.");
    } catch {
      setActionMessage("Unable to copy the scenario JSON from this browser context.");
    }
  }

  function handleDownloadPatch() {
    if (!result) {
      return;
    }
    downloadTextFile(`${result.runId}_policy_patch.yaml`, policyPatchYaml, "text/yaml;charset=utf-8");
    setActionMessage("Policy patch downloaded.");
  }

  return (
    <div className="prometheus-shell demo-shell">
      <header className="hero-bar">
        <div className="brand-block">
          <div>
            <div className="brand-wordmark">Zero-Day Sentinel</div>
            <div className="brand-tag">Threat Intel to Policy in Minutes</div>
          </div>
        </div>
        <div className="tenant-block">
          <div className="tenant-detail">{tenantDescriptor || "AI Operations Control Plane"}</div>
          <div className="tenant-label">{tenantName}</div>
          <div className="tenant-meta">
            <span>{geminiStatus.headline}</span>
            <span>{lobsterTrapStatus.headline}</span>
            <span>PROMETHEUS v{snapshot.productVersion}</span>
          </div>
        </div>
        <div className="hero-controls">
          <button
            className="btn-ghost"
            type="button"
            onClick={() => {
              setInput(defaultInput(snapshot.activePolicyPack));
              setActionMessage(null);
              setError(null);
            }}
          >
            Load Safe Sample
          </button>
          <button
            className="btn-demo"
            type="button"
            onClick={() => startTransition(() => void submit(false))}
            disabled={busy}
          >
            Analyze Threat
          </button>
          <button
            className="btn-redteam"
            type="button"
            onClick={() => startTransition(() => void submit(true))}
            disabled={busy}
          >
            Analyze + Run Safe Simulation
          </button>
        </div>
      </header>

      <main className="content-grid">
        <div className="content-main">
          <section className="panel">
            <div className="panel-head">
              <div>
                <div className="eyebrow">Threat report input</div>
                <h2>Turn a new report into policy, tests, and evidence</h2>
              </div>
            </div>
            <div className="prompt-tester">
              <input
                value={input.title}
                onChange={(event) => setInput((current) => ({ ...current, title: event.target.value }))}
              />
              <input
                value={input.source}
                onChange={(event) => setInput((current) => ({ ...current, source: event.target.value }))}
              />
              <div className="scenario-filters">
                <input
                  value={input.industry}
                  onChange={(event) => setInput((current) => ({ ...current, industry: event.target.value }))}
                />
                <select
                  value={input.policyPack}
                  onChange={(event) => setInput((current) => ({ ...current, policyPack: event.target.value }))}
                >
                  {snapshot.policyPacks.map((pack) => (
                    <option key={pack.id} value={pack.id}>
                      {pack.label}
                    </option>
                  ))}
                </select>
              </div>
              <textarea
                rows={12}
                value={input.reportText}
                onChange={(event) => setInput((current) => ({ ...current, reportText: event.target.value }))}
              />
              {error ? <p className="integration-note">{error}</p> : null}
              {actionMessage ? <p className="integration-note">{actionMessage}</p> : null}
            </div>
          </section>

          <section className="panel panel-side-by-side">
            <div>
              <div className="panel-head compact">
                <div>
                  <div className="eyebrow">Extraction results</div>
                  <h3>Defensive pattern extraction</h3>
                </div>
              </div>
              {result ? (
                <div className="related-events">
                  <div className="related-event">
                    <span>Threat summary</span>
                    <strong>{result.extraction.threatSummary}</strong>
                  </div>
                  <div className="related-event">
                    <span>Attacker goal</span>
                    <strong>{result.extraction.attackerGoal}</strong>
                  </div>
                  <div className="related-event">
                    <span>AI misuse pattern</span>
                    <strong>{result.extraction.aiMisusePattern}</strong>
                  </div>
                  <div className="related-event">
                    <span>Risky agent behaviors</span>
                    <strong>{result.extraction.riskyAgentBehaviors.join(", ")}</strong>
                  </div>
                  <div className="related-event">
                    <span>Dangerous tool calls</span>
                    <strong>{result.extraction.dangerousToolCalls.join(", ")}</strong>
                  </div>
                  <div className="related-event">
                    <span>Suspected tactics</span>
                    <strong>{result.extraction.suspectedTactics.join(", ")}</strong>
                  </div>
                  <div className="related-event">
                    <span>Affected functions</span>
                    <strong>{result.extraction.affectedEnterpriseFunctions.join(", ")}</strong>
                  </div>
                </div>
              ) : (
                <p className="control-copy">Analyze a threat report to extract structured defensive intelligence.</p>
              )}
            </div>

            <div>
              <div className="panel-head compact">
                <div>
                  <div className="eyebrow">Mitigation coverage</div>
                  <h3>Controls mapped from the report</h3>
                </div>
              </div>
              {result ? (
                <div className="queue-list">
                  {mitigationRows.map((item) => (
                    <article key={item.key} className="queue-card mitigation-card">
                      <div className="queue-top">
                        <div>
                          <div className="queue-title">{item.label}</div>
                          <div className="queue-meta">{item.covered ? "Covered" : "Not in this report"}</div>
                        </div>
                        <div className={`proof-chip ${item.covered ? "proof-chip-covered" : "proof-chip-muted"}`}>
                          {item.covered ? "✓" : "·"}
                        </div>
                      </div>
                      <div className="queue-detail-row">
                        <span>Generated rule: {item.generatedRule}</span>
                        <span>Gateway decision: {item.gatewayDecision}</span>
                        <span>Permission control: {item.permissionControl}</span>
                      </div>
                    </article>
                  ))}
                </div>
              ) : (
                <p className="control-copy">The coverage map links extracted risks to rules, permissions, and enforcement proof.</p>
              )}
            </div>
          </section>

          <section className="panel">
            <div className="panel-head">
              <div>
                <div className="eyebrow">Generated policy patch</div>
                <h2>Recommended guardrails</h2>
              </div>
              {result ? (
                <div className="threat-actions">
                  <button className="btn-ghost" type="button" onClick={() => void handleCopyYaml()}>
                    Copy YAML
                  </button>
                  <button className="btn-ghost" type="button" onClick={handleDownloadPatch}>
                    Download policy patch
                  </button>
                  <button
                    className="btn-ghost"
                    type="button"
                    onClick={() => void handleCopyScenario()}
                    disabled={!result.generatedScenario}
                  >
                    Copy scenario JSON
                  </button>
                </div>
              ) : null}
            </div>
            {result ? (
              <div className="threat-policy-grid">
                <div className="queue-list">
                  {result.policyPatch.map((rule) => (
                    <article key={rule.ruleName} className="queue-card">
                      <div className="queue-top">
                        <div>
                          <div className="queue-title">{rule.ruleName}</div>
                          <div className="queue-meta">{rule.action}</div>
                        </div>
                      </div>
                      <div className="queue-detail-row">
                        <span>{rule.condition}</span>
                      </div>
                      <p className="control-copy">{rule.reason}</p>
                    </article>
                  ))}
                </div>
                <div className="drawer-block threat-yaml-shell">
                  <div className="drawer-label">Generated policy patch YAML</div>
                  <pre className="report-preview threat-yaml-block">{policyPatchYaml}</pre>
                </div>
              </div>
            ) : (
              <p className="control-copy">Prometheus will suggest YAML-like policy changes for the new pattern.</p>
            )}
          </section>

          <section className="panel panel-side-by-side">
            <div>
              <div className="panel-head compact">
                <div>
                  <div className="eyebrow">Generated scenario</div>
                  <h3>Safe adversarial simulation</h3>
                </div>
              </div>
              {result?.generatedScenario ? (
                <div className="command-grid threat-command-grid">
                  <div className="command-item">
                    <span>Scenario</span>
                    <strong>{result.generatedScenario.name}</strong>
                  </div>
                  <div className="command-item">
                    <span>Declared intent</span>
                    <strong>{result.generatedScenario.declaredIntent}</strong>
                  </div>
                  <div className="command-item">
                    <span>Detected intent</span>
                    <strong>{result.generatedScenario.detectedIntent}</strong>
                  </div>
                  <div className="command-item">
                    <span>Attempted tool</span>
                    <strong>{result.generatedScenario.attemptedTool}</strong>
                  </div>
                  <div className="command-item span-2">
                    <span>Prompt</span>
                    <strong>{result.generatedScenario.prompt}</strong>
                  </div>
                  <div className="command-item">
                    <span>Expected decision</span>
                    <strong>{result.generatedScenario.expectedDecision}</strong>
                  </div>
                  <div className="command-item">
                    <span>Safety note</span>
                    <strong>{result.generatedScenario.safetyNote}</strong>
                  </div>
                </div>
              ) : (
                <p className="control-copy">The safe scenario uses synthetic cyber tools only and never includes exploit instructions.</p>
              )}
            </div>

            <div>
              <div className="panel-head compact">
                <div>
                  <div className="eyebrow">Safe by design</div>
                  <h3>Why this simulation stays enterprise-safe</h3>
                </div>
              </div>
              <div className="drawer-block safe-design-shell">
                <div className="evidence-badge">Synthetic cyber tool path only</div>
                <ul className="threat-checklist">
                  {SAFE_BY_DESIGN_POINTS.map((item) => (
                    <li key={item}>{item}</li>
                  ))}
                </ul>
              </div>
            </div>
          </section>

          <section className="panel">
            <div className="panel-head">
              <div>
                <div className="eyebrow">Gateway enforcement result</div>
                <h2>Live Agent Tool Gateway proof</h2>
              </div>
              {proofLabel ? <div className={`proof-badge ${proofTone}`}>{proofLabel}</div> : null}
            </div>
            {gatewayDecision ? (
              <>
                <div className="command-grid threat-proof-grid">
                  <div className="command-item">
                    <span>Attempted tool</span>
                    <strong>{result?.generatedScenario?.attemptedTool ?? gatewayDecision.toolName}</strong>
                  </div>
                  <div className="command-item">
                    <span>Decision</span>
                    <strong>{gatewayDecision.decision}</strong>
                  </div>
                  <div className="command-item">
                    <span>Tool executed</span>
                    <strong>{asBooleanLabel(gatewayDecision.toolExecuted)}</strong>
                  </div>
                  <div className="command-item">
                    <span>Side effect prevented</span>
                    <strong>{asBooleanLabel(gatewayDecision.sideEffectPreventedFlag)}</strong>
                  </div>
                  <div className="command-item">
                    <span>Risk score</span>
                    <strong>{gatewayDecision.riskScore.toFixed(2)}</strong>
                  </div>
                  <div className="command-item">
                    <span>Matched rules count</span>
                    <strong>{gatewayDecision.matchedRules.length}</strong>
                  </div>
                  <div className="command-item">
                    <span>DPI source</span>
                    <strong>{lobsterTrapSourceLabel(gatewayDecision)}</strong>
                  </div>
                  <div className="command-item">
                    <span>DPI mode</span>
                    <strong>{gatewayDecision.dpiMode}</strong>
                  </div>
                  <div className="command-item">
                    <span>Gemini mode</span>
                    <strong>{geminiMode}</strong>
                  </div>
                  <div className="command-item">
                    <span>Request ID</span>
                    <strong>{gatewayDecision.requestId}</strong>
                  </div>
                  <div className="command-item">
                    <span>Incident ID</span>
                    <strong>{incidentId ?? "Not generated"}</strong>
                  </div>
                  <div className="command-item">
                    <span>Audit hash</span>
                    <strong>{auditHash ?? "Pending"}</strong>
                  </div>
                  <div className="command-item">
                    <span>Timestamp</span>
                    <strong>{formatTimestamp(gatewayDecision.createdAt)}</strong>
                  </div>
                  <div className="command-item span-2">
                    <span>Reason</span>
                    <strong>{gatewayDecision.reason}</strong>
                  </div>
                  <div className="command-item span-2">
                    <span>Side effect prevented summary</span>
                    <strong>{gatewayDecision.sideEffectPrevented ?? gatewayDecision.toolResult?.sideEffectSummary ?? "No additional side effect summary recorded."}</strong>
                  </div>
                </div>

                <details className="integration-debug threat-evidence-shell">
                  <summary>View enforcement evidence</summary>
                  <div className="drawer-grid threat-evidence-grid">
                    <div className="drawer-card">
                      <div className="drawer-label">Raw Lobster Trap output preview</div>
                      <pre className="drawer-json threat-evidence-preview">{rawEvidencePreview}</pre>
                    </div>
                    <div className="drawer-card">
                      <div className="drawer-label">Matched policy rules</div>
                      <ul>
                        {gatewayDecision.matchedRules.length > 0 ? (
                          gatewayDecision.matchedRules.map((rule) => <li key={rule}>{rule}</li>)
                        ) : (
                          <li>No explicit policy rules were returned.</li>
                        )}
                      </ul>
                    </div>
                    <div className="drawer-card">
                      <div className="drawer-label">Permission evaluation</div>
                      <p>{gatewayDecision.permissionEvaluation.permissionState}</p>
                      <p>{gatewayDecision.permissionEvaluation.reason}</p>
                      <p>
                        Restrictions:{" "}
                        {gatewayDecision.permissionEvaluation.matchedRestrictions.length > 0
                          ? gatewayDecision.permissionEvaluation.matchedRestrictions.join(", ")
                          : "No additional restrictions returned."}
                      </p>
                    </div>
                    <div className="drawer-card">
                      <div className="drawer-label">Tribunal decision</div>
                      <p>{tribunalSummary}</p>
                    </div>
                    <div className="drawer-card">
                      <div className="drawer-label">Safety note</div>
                      <p>{result?.generatedScenario?.safetyNote ?? "Synthetic adversarial simulation only."}</p>
                    </div>
                    <div className="drawer-card">
                      <div className="drawer-label">Fallback used</div>
                      <p>{asBooleanLabel(fallbackUsed)}</p>
                      <p>{gatewayDecision.evidencePreview ?? "Compact evidence preview unavailable."}</p>
                    </div>
                  </div>
                </details>
              </>
            ) : (
              <p className="control-copy">
                Run a safe simulation to route this generated cyber tool call through the live Agent Tool Gateway.
              </p>
            )}
          </section>

          <section className="panel">
            <div className="panel-head">
              <div>
                <div className="eyebrow">Before / after</div>
                <h2>Why this is a control-plane feature, not just a threat report reader</h2>
              </div>
            </div>
            <div className="command-grid threat-proof-triptych">
              <div className="command-item">
                <span>Before</span>
                <strong>
                  Threat reports remain passive reading material. Security teams still need to manually translate them
                  into controls, tests, and audit evidence.
                </strong>
              </div>
              <div className="command-item">
                <span>After</span>
                <strong>
                  Prometheus converts threat intelligence into policy rules, safe adversarial scenarios, gateway
                  enforcement, and audit-ready proof in minutes.
                </strong>
              </div>
              <div className="command-item">
                <span>Proof</span>
                <strong>
                  exploit.generate was attempted in a synthetic agent workflow and blocked before execution by the live
                  Agent Tool Gateway.
                </strong>
              </div>
            </div>
          </section>
        </div>

        <aside className="content-rail">
          <section className="panel rail-panel">
            <div className="panel-head compact">
              <div>
                <div className="eyebrow">Recent runs</div>
                <h3>Zero-Day Sentinel history</h3>
              </div>
            </div>
            <div className="stream-list">
              {runs.length > 0 ? (
                runs.map((run) => (
                  <button
                    key={run.runId}
                    className={`stream-card run-history-card${selectedRunId === run.runId ? " selected" : ""}`}
                    type="button"
                    onClick={() => startTransition(() => void restoreRun(run.runId))}
                    disabled={restoringRunId === run.runId}
                  >
                    <div className="stream-top">
                      <span>{run.title}</span>
                      <span>{run.decision ?? "No simulation"}</span>
                    </div>
                    <div className="stream-actions">
                      <span>Tool: {run.attemptedTool ?? "Not generated"}</span>
                      <span>Executed: {asBooleanLabel(run.toolExecuted)}</span>
                      <span>Created: {formatTimestamp(run.createdAt)}</span>
                    </div>
                    <div className="stream-foot">
                      <span className="stream-consensus">{run.incidentId ?? "No incident"}</span>
                      <span className={`proof-chip ${selectedRunId === run.runId ? "proof-chip-covered" : "proof-chip-muted"}`}>
                        {restoringRunId === run.runId ? "Loading" : "Restore"}
                      </span>
                    </div>
                  </button>
                ))
              ) : (
                <p>No persisted runs yet.</p>
              )}
            </div>
          </section>
        </aside>
      </main>
    </div>
  );
}
