# PROMETHEUS v0.4.0 Local Demo

## Start the stack

```bash
pnpm install
cd apps/api
uv sync
cd ../..
python scripts/seed.py
pnpm dev
```

## Verify integrations

- `http://localhost:8000/health`
- `http://localhost:8000/api/integrations/status`
- `http://localhost:8000/api/lobstertrap/debug`

## Open these routes

- `http://localhost:3000/`
- `http://localhost:3000/demo`
- `http://localhost:3000/scenarios`
- `http://localhost:3000/threat-intel`

## Live demo sequence

1. Show the dashboard and integration status.
2. Show `Gemini connected`.
3. Show `Veea Lobster Trap DPI floor: LIVE CLI`.
4. Run a safe path and show a permitted tool call.
5. Run a blocked or quarantined path in Scenario Lab or the dashboard.
6. Open `/threat-intel` and run Zero-Day Sentinel.
7. Point to the proof card showing `exploit.generate` blocked before execution.
8. Generate the audit bundle.

## Safe verification commands

```bash
python scripts/smoke_gateway.py
python scripts/smoke_threat_intel.py
pnpm screenshots
```

## Expected screenshot set

- dashboard
- integration status
- evidence drawer
- audit bundle
- demo route
- scenario lab
- threat intel

Saved under:

- `apps/web/public/screenshots/final/`
