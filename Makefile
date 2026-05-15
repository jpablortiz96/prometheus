dev:
	pnpm dev

test:
	cd apps/api && uv run python -m pytest

build:
	pnpm --filter @prometheus/web build

seed:
	python scripts/seed.py

init-db:
	python scripts/init_db.py

screenshots:
	node scripts/capture_screenshots.mjs
