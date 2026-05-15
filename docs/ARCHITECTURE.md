# PROMETHEUS Architecture

## Objective

PROMETHEUS is an enterprise AI agent governance layer that prevents unsafe tool execution, preserves deterministic evidence, and creates regulator-readable audit output without depending on a live commercial model.

Prometheus is not just observing agent behavior. It sits in the execution path as an Agent Tool Gateway, preventing unsafe tool calls before they reach enterprise systems.

## Core services

### Watcher

- built on Veea Lobster Trap DPI proxy concepts
- parses prompt content, intent mismatch, risky commands, sensitive paths, domains, and regulated data indicators
- emits normalized policy signals and `_lobstertrap` metadata

### Agent Tool Gateway

- receives attempted enterprise tool calls before execution
- runs Lobster Trap inspection, Prophet prediction, permission checks, and Tribunal escalation in sequence
- returns `ALLOW`, `BLOCK`, `QUARANTINE`, or `HUMAN_REVIEW`
- only executes sandbox tools when the final decision is `ALLOW`

### Permission engine

- loads the agent-to-tool permission matrix from `apps/api/prometheus/data/permissions.json`
- evaluates explicit allow or deny rules, human-review and quarantine paths
- overlays policy pack restrictions, data classification, external egress, and refund thresholds

### Sandbox tools

- provides safe enterprise tool shims for CRM, finance, contracts, docs, refunds, and email
- extends into safe cyber-defense stubs for `vuln.research`, `report.write`, `scanner.run`, `exploit.generate`, `exploit.execute`, and `auth.bypass_test`
- preserves side-effect summaries and data-classification labels for downstream evidence
- never calls real external systems

### Zero-Day Sentinel

- ingests emerging threat reports and converts them into defensive structured intelligence
- uses Gemini when available, otherwise deterministic fallback
- proposes policy patches and permission changes for the security agent lane
- generates a safe synthetic cyber scenario and routes it through the Agent Tool Gateway
- proves dangerous cyber tools were blocked before execution and seals audit evidence

### Lobster Trap bridge

- simulated by default
- optional CLI mode when `LOBSTERTRAP_BIN` is configured
- validates `infra/lobstertrap/prometheus_policy.yaml`
- exposes policy rule count and normalized inspection metadata

### Prophet

- powered by Gemini model routing when available
- predicts expected next action
- computes divergence against observed behavior
- falls back deterministically if Gemini is missing or invalid

### Tribunal

- three judges: Aegis, Themis, Dike
- converts technical evidence into an allow, block, quarantine, or escalate decision
- keeps structured JSON output and deterministic fallback

### Trust engine

- updates trust scores, divergence, KPI rollups, and business-facing metrics

### Historian

- generates regulator-readable Markdown and HTML reports
- generates tamper-evident audit bundles with hashes
- stores report archive metadata in SQLite when available

## Storage model

SQLite primary path:

- `apps/api/prometheus/data/prometheus.db`

Tables:

- `runtime_state`
- `agents`
- `incidents`
- `events`
- `human_reviews`
- `audit_reports`
- `scenario_runs`
- `tool_calls`
- `gateway_decisions`
- `permission_evaluations`
- `document_inspections`
- `audit_bundles`
- `sandbox_notes`
- `threat_intel_runs`

Fallback behavior:

- runtime JSON still exists for deterministic recovery
- if SQLite fails to initialize, the app continues in fallback mode

## Frontend surfaces

- `/` full enterprise control plane
- `/demo` deterministic 3-minute judge route
- `/scenarios` scenario lab and custom prompt tester
- `/threat-intel` Zero-Day Sentinel

Key dashboard modules:

- Incident Command Center
- Evidence Drawer
- Agent Tool Gateway
- Agent Permission Matrix
- Human Review Queue
- Policy Pack Switcher
- Integration Status
- Prediction Stream
- Incident History
- Report Archive
- Knowledge Graph
- Enterprise ROI panel
- Document Attack Lab on `/scenarios`
- Zero-Day Sentinel on `/threat-intel`

## Backend endpoints

- `GET /health`
- `GET /api/snapshot`
- `GET /api/agents`
- `GET /api/events`
- `GET /api/kpis`
- `GET /api/integrations/status`
- `GET /api/incidents`
- `GET /api/incidents/{incident_id}`
- `GET /api/audit/reports`
- `GET /api/gateway/permissions`
- `GET /api/gateway/tool-calls`
- `GET /api/gateway/tool-calls/{request_id}`
- `GET /api/scenarios`
- `GET /api/stream/events`
- `POST /api/red-team/run`
- `POST /api/policy-pack/select`
- `POST /api/review/action`
- `POST /api/tribunal/evaluate`
- `POST /api/audit/report`
- `POST /api/audit/report/markdown`
- `POST /api/audit/report/html`
- `POST /api/audit/bundle`
- `POST /api/gateway/tool-call`
- `POST /api/gateway/replay/{request_id}`
- `POST /api/documents/inspect`
- `POST /api/threat-intel/analyze`
- `POST /api/lobstertrap/inspect`
- `POST /api/scenarios/run`
- `GET /api/threat-intel/runs`
- `GET /api/threat-intel/runs/{run_id}`

## Security model

1. Tool requests enter the Agent Tool Gateway before execution.
2. Deterministic inspection happens first.
3. Behavioral prediction checks whether the agent stayed inside its expected lane.
4. Permission evaluation constrains the action by agent, tool, policy pack, and egress risk.
5. Tribunal explains the final decision when risk is high or the intent mismatches.
6. Human reviewers can override or escalate.
7. Historian preserves evidence, rationale, and remediation.

Threat-intel path:

1. Threat report enters Zero-Day Sentinel.
2. Defensive patterns are extracted from the report.
3. Policy patches and permission changes are proposed.
4. A safe adversarial scenario is generated with synthetic cyber tools only.
5. The scenario is routed through the Agent Tool Gateway.
6. Dangerous cyber tools are blocked, quarantined, or held for review before execution.
7. Audit evidence is sealed for sponsor and judge review.

## Why this is enterprise-ready

- deterministic fallback means the demo never depends on live model availability
- sponsor technologies are visible in evidence, status, and reports
- policy packs map to common enterprise regimes
- judge routes are optimized for laptops and short live demos
