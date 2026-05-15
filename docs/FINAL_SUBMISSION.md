# PROMETHEUS v0.4.0 Final Submission

## Repository positioning

PROMETHEUS should present as a serious enterprise AI security startup, not a prompt-filtering demo. The core narrative is:

> PROMETHEUS is not just observing agent behavior. It sits in the execution path as an Agent Tool Gateway, preventing unsafe tool calls before they reach enterprise systems.

## Public repo checklist

Before pushing:

1. verify no `.env` is committed
2. verify no API keys are committed
3. verify no `.venv` is committed
4. verify no `node_modules` is committed
5. verify README renders
6. run tests
7. run smoke scripts

## Required proof points

- Gemini connected
- Veea Lobster Trap `live_cli`
- safe CRM call allowed
- dangerous external email blocked
- poisoned document blocked
- Zero-Day Sentinel run showing `exploit.generate` blocked before execution
- audit hash visible

## Final commands

```bash
pnpm --filter @prometheus/web typecheck
pnpm --filter @prometheus/web build
cd apps/api
uv run python -m pytest
cd ../..
python scripts/smoke_gateway.py
python scripts/smoke_threat_intel.py
pnpm screenshots
```

## Submission artifacts

- `README.md`
- `docs/DEPLOYMENT.md`
- `docs/LOCAL_DEMO.md`
- `submission/PROJECT_SUMMARY.md`
- `submission/THREE_MINUTE_PITCH.md`
- `submission/TECHNICAL_WRITEUP.md`
- `submission/JUDGING_CRITERIA_MAPPING.md`
- `submission/VEEA_AWARD_WRITEUP.md`
- `submission/GEMINI_AWARD_WRITEUP.md`
- `submission/DEMO_CHECKLIST.md`
