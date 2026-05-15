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
    from prometheus.services.seeder import build_seed_snapshot  # noqa: E402

    runtime_path = API_ROOT / "prometheus" / "data" / "runtime_state.json"
    snapshot = build_seed_snapshot(Settings())
    runtime_path.write_text(
        snapshot.model_dump_json(by_alias=True, indent=2),
        encoding="utf-8",
    )
    print(f"Seeded PROMETHEUS runtime state -> {runtime_path}")


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
