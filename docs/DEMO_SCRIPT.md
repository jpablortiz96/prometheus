# PROMETHEUS Demo Script

## Goal

Show that PROMETHEUS is not only detecting attacks. It is predicting safe behavior, stopping unsafe execution, and producing an audit artifact an enterprise team could actually use.

## Recommended route

Use `/demo` for the cleanest 3-minute path. Use `/` if judges want to inspect the full control plane. Use `/scenarios` if they ask for a live adversarial test.

## 3-minute flow

### Minute 0 to 1

1. Open `http://localhost:3000/demo`
2. Say:
   `Enterprise AI agents are already operating across CRM, finance, support, code, and documents.`
3. Point to the judge stepper and say:
   `PROMETHEUS starts from normal operations, then shows how an enterprise incident moves from detection to decision to audit.`

### Minute 1 to 2

1. Click `Next Step` to `Attack Injected`
2. Say:
   `A manipulated document tries to redirect an agent from normal indexing into privileged audit extraction.`
3. Click `Next Step` again to `DPI Evidence`
4. Say:
   `Veea Lobster Trap-style DPI gives us the deterministic floor: intent mismatch, policy match, and evidence we can trust.`
5. Click `Next Step` to `Prediction Divergence`
6. Say:
   `Gemini-powered Prophet predicts the safe next action and compares it to the actual observed behavior.`

### Minute 2 to 3

1. Click `Next Step` to `Tribunal Verdict`
2. Say:
   `Now PROMETHEUS moves from detection into enterprise decisioning. Aegis, Themis, and Dike vote whether to allow, block, quarantine, or escalate.`
3. Click `Generate Report`
4. Say:
   `Historian seals a regulator-readable report and tamper-evident audit bundle in the same control path.`
5. Close with:
   `Blocked before tool execution. Audit-ready in under 300 milliseconds.`

## Optional full dashboard flow

1. Open `/`
2. Toggle `Presentation Mode`
3. Click `Red Team Drill`
4. Open the Evidence Drawer from Prediction Stream
5. Show the Integration Status panel
6. Click `Generate Regulator Report`
7. Click `Generate Audit Bundle`

## Keyboard shortcuts

- `D` = run Demo Mode
- `R` = run Red Team Drill
- `J` = toggle Judge Mode
- `P` = toggle Presentation Mode
- `G` = generate Regulator Report

## Fallback if internet fails

- keep `GEMINI_API_KEY` unset or disconnected
- demo still works in deterministic mode
- explain:
  `PROMETHEUS was designed so the control plane does not fail just because a live model or external dependency is unavailable.`
