# Lobster Trap Integration Notes

PROMETHEUS treats Lobster Trap as the deterministic DPI policy floor.

## What runs today

- `infra/lobstertrap/prometheus_policy.yaml` defines the rule pack mirrored by `apps/api/prometheus/services/watcher.py`.
- If Lobster Trap is not installed, the app still runs in deterministic demo mode with the same policy semantics.
- The FastAPI watcher emits `_lobstertrap`-style metadata so the dashboard and audit report still have sponsor-visible inspection traces.

## If Lobster Trap is installed

Use the PROMETHEUS pack as the baseline config:

```bash
lobstertrap serve --config infra/lobstertrap/prometheus_policy.yaml
```

Run a local test case against the policy layer:

```bash
lobstertrap test --config infra/lobstertrap/prometheus_policy.yaml
```

## Integration contract

- Lobster Trap decides the deterministic policy floor.
- PROMETHEUS layers behavioral prediction, three-judge tribunal reasoning, trust scoring, and regulator-readable audit narratives above it.
- If the live proxy fails or is absent, PROMETHEUS falls back to local deterministic inspection so the demo never breaks.
