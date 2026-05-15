# PROMETHEUS v0.4.0 Demo Checklist

## Commands

```bash
pnpm install
cd apps/api
uv sync
cd ../..
python scripts/seed.py
pnpm dev
python scripts/smoke_gateway.py
python scripts/smoke_threat_intel.py
pnpm screenshots
```

## Browser tabs

1. `http://localhost:3000/`
2. `http://localhost:3000/demo`
3. `http://localhost:3000/scenarios`
4. `http://localhost:3000/threat-intel`

## Proof points to show

- Gemini connected
- Veea Lobster Trap `live_cli`
- safe CRM call allowed
- dangerous email blocked before execution
- poisoned document blocked before execution
- Zero-Day Sentinel proof card
- audit hash visible

## Screenshot set

- dashboard
- integration status
- demo route
- scenario lab
- threat intel
- evidence drawer
- audit bundle

Saved to:

- `apps/web/public/screenshots/final/`

## Final submission checklist

- [ ] README updated
- [ ] docs updated
- [ ] submission docs updated
- [ ] screenshots captured
- [ ] backend tests passing
- [ ] frontend build passing
- [ ] smoke scripts passing
- [ ] no `.env` staged
- [ ] no API keys staged
- [ ] no `.venv` staged
- [ ] no `node_modules` staged
