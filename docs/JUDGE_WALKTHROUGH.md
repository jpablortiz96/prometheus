# Judge Walkthrough

PROMETHEUS v0.4.0 adds Zero-Day Sentinel proof polish so judges can see policy generation, blocked tool execution, and audit evidence in one page.

## Three-minute path

1. Open the dashboard
   - `http://localhost:3000/demo` for the cleanest route
   - or `http://localhost:3000` for the full control plane

2. Show normal agent operations
   - explain that enterprise agents already operate across CRM, finance, support, code, and documents
   - highlight trust scores, policy packs, the Agent Permission Matrix, and enterprise governance framing

3. Trigger the attack
   - on `/demo`, let the route progress until `Gateway Intercept`
   - call out that the demo first executes `docs.index`, then intercepts `contracts.rewrite`
   - on `/`, use `Red Team Drill` or open `/scenarios` and run a gateway-backed scenario

4. Open the Evidence Drawer
   - click the blocked gateway event in Prediction Stream
   - show raw prompt, matched policy rules, DPI findings, target domains, risky commands, raw Lobster Trap output, policy file used, and CLI execution timing

5. Show the Tribunal verdict
   - explain that Aegis, Themis, and Dike convert telemetry into an enterprise decision
   - emphasize expected-vs-observed divergence plus permission enforcement, not only prompt filtering
   - say clearly: `Blocked before tool execution.`

6. Generate the report
   - click `Generate Regulator Report`
   - then click `Generate Audit Bundle`
   - point out the tamper-evident audit hash, the Historian seal, and the preserved gateway decision

7. Close on enterprise value
   - say:
     `Lobster Trap gives us the deterministic DPI floor. Gemini gives us structured prediction and reasoning. Prometheus sits in the execution path as an Agent Tool Gateway, preventing unsafe tool calls before they reach enterprise systems.`

8. Show Zero-Day Sentinel if judges want a fresh threat-intel story
   - open `http://localhost:3000/threat-intel`
   - load the safe sample threat report
   - click `Analyze + Run Safe Simulation`
   - highlight the policy patch YAML, the generated scenario, and the blocked `exploit.generate` proof card
   - say:
     `Prometheus can turn emerging AI threat intelligence into enforceable controls, safe adversarial tests, and audit evidence in minutes.`

## If judges ask for interactive validation

1. Open `http://localhost:3000/scenarios`
2. Filter by policy pack or department
3. Run one scenario live so it maps to a real tool attempt
4. Use the Document Attack Lab with `poisoned_supplier_contract.md`

## If live model credentials fail

Say:

`The demo is intentionally designed to remain fully operational without external model credentials. We degrade into deterministic simulation instead of failing the control plane.`
