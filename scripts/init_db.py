from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
API_ROOT = ROOT / "apps" / "api"


def _run_internal() -> None:
    if str(API_ROOT) not in sys.path:
        sys.path.insert(0, str(API_ROOT))

    from prometheus.core.config import Settings  # noqa: E402
    from prometheus.repositories.database import DatabaseManager  # noqa: E402
    from prometheus.repositories.events import EventsRepository  # noqa: E402
    from prometheus.repositories.incidents import IncidentsRepository  # noqa: E402
    from prometheus.services.seeder import build_seed_snapshot  # noqa: E402

    settings = Settings()
    snapshot = build_seed_snapshot(settings)
    database = DatabaseManager(settings)
    events = EventsRepository(database)
    incidents = IncidentsRepository(database)

    if not database.initialize():
        raise RuntimeError(
            f"Could not initialize SQLite database at {database.path}: {database.error}"
        )

    database.clear_all()
    database.save_runtime_state(snapshot)
    events.upsert_agents(snapshot.agents)
    events.upsert_events(snapshot.events)
    incidents.upsert_from_events(snapshot.events)
    print(f"Initialized PROMETHEUS SQLite database -> {database.path}")


def main() -> None:
    if "--internal" in sys.argv:
        _run_internal()
        return

    try:
        _run_internal()
    except ModuleNotFoundError:
        subprocess.run(
            ["uv", "run", "python", str(Path(__file__).resolve()), "--internal"],
            cwd=API_ROOT,
            check=True,
        )


if __name__ == "__main__":
    main()
