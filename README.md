# PROMETHEUS
### Pre-Crime Governance for Enterprise AI Agents

The execution-path control plane that inspects, predicts, blocks, and audits unsafe AI agent actions before they reach enterprise systems.

![PROMETHEUS v0.4.0](https://img.shields.io/badge/PROMETHEUS-v0.4.0-111827?style=flat-square)
![Veea Lobster Trap: Live CLI](https://img.shields.io/badge/Veea_Lobster_Trap-Live_CLI-0f766e?style=flat-square)
![Gemini: Connected](https://img.shields.io/badge/Gemini-Connected-1d4ed8?style=flat-square)
![Agent Tool Gateway](https://img.shields.io/badge/Agent_Tool_Gateway-Active-7c3aed?style=flat-square)
![Audit-ready](https://img.shields.io/badge/Audit-ready-f59e0b?style=flat-square)
![Zero-Day Sentinel](https://img.shields.io/badge/Zero--Day_Sentinel-Enabled-be185d?style=flat-square)
![Hackathon Build](https://img.shields.io/badge/Hackathon-Build-334155?style=flat-square)

![PROMETHEUS Dashboard](./apps/web/public/screenshots/final/dashboard.png)

Enterprise AI agents are moving from chat to action. PROMETHEUS is the governance layer that makes those actions inspectable, controllable, and auditable.

## Why PROMETHEUS exists

Enterprise AI agents can query CRMs, summarize contracts, send emails, reconcile finance data, index documents, and trigger workflows.

But security teams still struggle to answer:

- What did the agent claim it was doing?
- What did it actually try to do?
- Which policy did it violate?
- Was the action blocked before execution?
- Can the decision be explained to compliance or a regulator?

PROMETHEUS sits directly in the agent execution path as an AI Agent Tool Gateway. It combines Veea Lobster Trap DPI, Gemini reasoning, permission controls, tribunal-style decisions, and audit bundles to stop unsafe tool calls before damage happens.

## Before and after

| Before PROMETHEUS | After PROMETHEUS |
|---|---|
| Agents act with limited visibility | Every tool call is inspected before execution |
| Logs are fragmented | Evidence is unified into an audit trail |
| Prompt injection is hard to trace | Lobster Trap extracts risk signals |
| Governance is manual | Policy packs and permission matrix enforce decisions |
| Reports are created after damage | Audit bundles are generated immediately |

## Product screenshots

| Control Plane | Live Integration Status |
|---|---|
| ![](./apps/web/public/screenshots/final/dashboard.png) | ![](./apps/web/public/screenshots/final/integration-status.png) |

| Evidence Drawer | Tribunal Modal |
|---|---|
| ![](./apps/web/public/screenshots/final/evidence-drawer.png) | ![](./apps/web/public/screenshots/final/tribunal-modal.png) |

| Scenario Lab | Zero-Day Sentinel |
|---|---|
| ![](./apps/web/public/screenshots/final/scenario-lab.png) | ![](./apps/web/public/screenshots/final/threat-intel.png) |

| Audit Bundle | Judge Mode |
|---|---|
| ![](./apps/web/public/screenshots/final/audit-bundle.png) | ![](./apps/web/public/screenshots/final/judge-mode.png) |

## Enterprise architecture

PROMETHEUS is built around one core principle: AI agent security must happen before tool execution, not after.

```mermaid
flowchart TB
    subgraph Inputs["Enterprise Inputs"]
        U["User Prompt"]
        D["Document / Contract"]
        T["Threat Intel Report"]
        A["AI Agent Request"]
    end

    subgraph Gateway["PROMETHEUS Agent Tool Gateway"]
        G["Tool Call Interceptor"]
        W["Watcher<br/>Intent + Risk Extraction"]
        P["Permission Engine<br/>Agent -> Tool Matrix"]
        R["Risk Scoring<br/>Trust + Divergence"]
    end

    subgraph Sponsors["Sponsor Technology Layer"]
        LT["Veea Lobster Trap CLI<br/>Deep Prompt Inspection"]
        GM["Gemini Model Router<br/>Prophet | Tribunal | Historian"]
    end

    subgraph Decision["Governance Decision Layer"]
        PR["Prophet<br/>Expected Action Prediction"]
        TR["Tribunal<br/>Aegis | Themis | Dike"]
        HR["Human Review Queue"]
    end

    subgraph Tools["Sandbox Enterprise Tools"]
        CRM["CRM Query"]
        EMAIL["External Email"]
        FIN["Finance Export"]
        DOCS["Document Index"]
        CONTRACT["Contract Rewrite"]
        CYBER["Synthetic Cyber Tools"]
    end

    subgraph Evidence["Audit + Evidence"]
        IC["Incident Command Center"]
        ED["Evidence Drawer"]
        AB["Audit Bundle + SHA-256 Hash"]
        RR["Regulator Report"]
        ZD["Zero-Day Sentinel"]
    end

    U --> G
    D --> G
    T --> ZD
    A --> G

    G --> LT
    LT --> W
    W --> GM
    W --> P
    P --> R
    R --> PR
    PR --> TR
    TR --> HR

    TR -->|"ALLOW"| CRM
    TR -->|"ALLOW"| DOCS
    TR -->|"BLOCK / QUARANTINE"| EMAIL
    TR -->|"BLOCK / QUARANTINE"| FIN
    TR -->|"BLOCK / HUMAN REVIEW"| CONTRACT
    TR -->|"BLOCK"| CYBER

    TR --> IC
    LT --> ED
    GM --> AB
    HR --> RR
    ZD --> G
```

## Execution path: the winning flow

```mermaid
flowchart LR
    I["Prompt / Document / Threat Report"] --> C["Attempted Tool Call"]
    C --> L["Lobster Trap DPI"]
    C --> M["Permission Matrix"]
    L --> P["Expected vs Observed Prediction"]
    P --> T["Tribunal / Human Review"]
    M --> T
    T -->|"ALLOW"| E["Safe Sandbox Execution"]
    T -->|"BLOCK / QUARANTINE"| B["Blocked Before Execution"]
    E --> A["Audit Bundle + Report"]
    B --> A
    A --> R["Compliance and Regulator Evidence"]
```

## Core product surfaces

### Agent Tool Gateway

PROMETHEUS does not just observe AI agents. It sits between agents and tools, deciding whether an action can execute.

It already demonstrates:

- `crm.query` allowed
- `email.send_external` blocked
- `contracts.rewrite` quarantined
- `exploit.generate` blocked

![PROMETHEUS Demo Route](./apps/web/public/screenshots/final/demo-route.png)

### Veea Lobster Trap integration

PROMETHEUS uses Veea Lobster Trap as the deterministic DPI floor.

The platform exposes sponsor-visible evidence for:

- `live_cli` mode
- raw output preview
- matched rules
- policy file used
- inspection timing
- fallback safety

![PROMETHEUS Integration Status](./apps/web/public/screenshots/final/integration-status.png)

### Gemini reasoning layer

Gemini powers:

- Prophet expected action prediction
- Tribunal reasoning
- Historian audit narrative
- Zero-Day Sentinel extraction

Gemini is not used blindly. Outputs are schema-validated and fall back safely when unavailable or invalid.

### Zero-Day Sentinel

Zero-Day Sentinel turns new AI threat reports into policy, safe scenarios, gateway enforcement, and audit evidence.

It is intentionally constrained:

- no exploit code
- no live targets
- synthetic cyber tools only
- `exploit.generate` blocked before execution

![Zero-Day Sentinel](./apps/web/public/screenshots/final/threat-intel.png)

### Scenario Lab

Scenario Lab lets judges and operators replay enterprise attack paths through the live Agent Tool Gateway.

![Scenario Lab](./apps/web/public/screenshots/final/scenario-lab.png)

### Audit Bundle

PROMETHEUS generates regulator-readable reports and tamper-evident bundles with SHA-256 hashes immediately after enforcement.

![Audit Bundle](./apps/web/public/screenshots/final/audit-bundle.png)

## Verified local smoke tests

```text
[PASS] Safe CRM call                  ALLOW      executed=true
[PASS] Dangerous external email       BLOCK      executed=false
[PASS] Dangerous contract rewrite     QUARANTINE executed=false
[PASS] Poisoned document inspection   BLOCK      executed=false
[PASS] Zero-Day Sentinel              BLOCK      exploit.generate executed=false
[PASS] Veea Lobster Trap              live_cli
[PASS] Gemini                         connected
```

These tests prove that PROMETHEUS is not just a dashboard. It intercepts live gateway requests and prevents dangerous tool calls before execution.

## Quickstart

```bash
pnpm install
cd apps/api
uv sync
cd ../..
python scripts/seed.py
pnpm dev
```

- Frontend: `http://localhost:3000`
- Backend: `http://localhost:8000`
- API Docs: `http://localhost:8000/docs`

## Environment

Root `.env`

```dotenv
NEXT_PUBLIC_API_URL=http://localhost:8000
```

`apps/api/.env`

```dotenv
GEMINI_API_KEY=your_gemini_api_key_here
GEMINI_REASONING_MODEL=gemini-3.1-pro-preview
GEMINI_FAST_MODEL=gemini-3-flash-preview
GEMINI_LITE_MODEL=gemini-3.1-flash-lite-preview
LOBSTERTRAP_ENABLED=true
LOBSTERTRAP_BIN=/path/to/lobstertrap
LOBSTERTRAP_POLICY_PATH=/path/to/prometheus_policy.yaml
LOBSTERTRAP_TIMEOUT_SECONDS=5
```

Safe examples are included in:

- `.env.example`
- `apps/api/.env.example`

## Lobster Trap setup

```bash
mkdir tools
cd tools
git clone https://github.com/veeainc/lobstertrap.git
cd lobstertrap
make build
```

Configure:

### Windows

```dotenv
LOBSTERTRAP_ENABLED=true
LOBSTERTRAP_BIN=C:\path\to\PROMETHEUS\tools\lobstertrap\lobstertrap.exe
LOBSTERTRAP_POLICY_PATH=C:\path\to\PROMETHEUS\infra\lobstertrap\prometheus_policy.yaml
LOBSTERTRAP_TIMEOUT_SECONDS=5
```

### macOS/Linux

```dotenv
LOBSTERTRAP_ENABLED=true
LOBSTERTRAP_BIN=/path/to/PROMETHEUS/tools/lobstertrap/lobstertrap
LOBSTERTRAP_POLICY_PATH=/path/to/PROMETHEUS/infra/lobstertrap/prometheus_policy.yaml
LOBSTERTRAP_TIMEOUT_SECONDS=5
```

Verification:

```bash
python scripts/smoke_gateway.py
```

## Routes

| Route | Purpose |
|---|---|
| `/` | Control plane dashboard |
| `/demo` | 3-minute guided judge demo |
| `/scenarios` | Scenario Lab |
| `/threat-intel` | Zero-Day Sentinel |
| `/docs` | API docs through FastAPI at backend |

## Judging criteria mapping

| Criteria | How PROMETHEUS addresses it |
|---|---|
| Practical enterprise value | Prevents unsafe agent actions before execution |
| Strong technical thinking | Execution-path gateway, DPI, Gemini routing, permissions, audit hash |
| Working demo | Local app, smoke tests, screenshots, API docs |
| Scalability | Gateway architecture, policy packs, SQLite-ready persistence, future connectors |
| Innovation | Threat Intel to Policy, Zero-Day Sentinel, Tribunal, blocked-before-execution proof |
| Sponsor usage | Veea Lobster Trap live CLI + Gemini reasoning layer |

## Safety statement

PROMETHEUS does not generate exploit code, scan live targets, send real emails, export real financial records, or modify real contracts. Dangerous tools are synthetic and are intentionally blocked or quarantined before execution.

## Built by

Juan Pablo Enriquez Ortiz  
Founder, Eduky
