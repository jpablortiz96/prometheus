from __future__ import annotations

import sqlite3
from pathlib import Path

from prometheus.core.config import Settings
from prometheus.models.domain import DashboardSnapshot


class DatabaseManager:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.path = self._resolve_database_path(settings.database_path)
        self.available = False
        self.error: str | None = None

    def _resolve_database_path(self, configured_path: str) -> Path:
        candidate = Path(configured_path)
        if candidate.is_absolute():
            return candidate
        return (Path(__file__).resolve().parents[2] / configured_path).resolve()

    def connection(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        return connection

    def initialize(self) -> bool:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.connection() as connection:
                connection.executescript(
                    """
                    PRAGMA journal_mode=WAL;

                    CREATE TABLE IF NOT EXISTS runtime_state (
                        id TEXT PRIMARY KEY,
                        snapshot_json TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS agents (
                        id TEXT PRIMARY KEY,
                        status TEXT NOT NULL,
                        trust_score INTEGER NOT NULL,
                        policy_pack TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        data TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS incidents (
                        incident_id TEXT PRIMARY KEY,
                        event_id TEXT NOT NULL,
                        scenario_id TEXT NOT NULL,
                        agent_id TEXT NOT NULL,
                        decision TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        risk_score REAL NOT NULL,
                        policy_pack TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        data TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS events (
                        event_id TEXT PRIMARY KEY,
                        incident_id TEXT NOT NULL,
                        scenario_id TEXT NOT NULL,
                        agent_id TEXT NOT NULL,
                        decision TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        review_status TEXT NOT NULL,
                        timestamp TEXT NOT NULL,
                        data TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS human_reviews (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        event_id TEXT NOT NULL,
                        incident_id TEXT NOT NULL,
                        action TEXT NOT NULL,
                        message TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        data TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS audit_reports (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        incident_id TEXT NOT NULL,
                        title TEXT NOT NULL,
                        generated_at TEXT NOT NULL,
                        format TEXT NOT NULL,
                        decision TEXT NOT NULL,
                        policy_pack TEXT NOT NULL,
                        audit_hash TEXT NOT NULL,
                        model_used TEXT NOT NULL,
                        data TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS audit_bundles (
                        incident_id TEXT PRIMARY KEY,
                        generated_at TEXT NOT NULL,
                        audit_hash TEXT NOT NULL,
                        data TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS scenario_runs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        scenario_id TEXT NOT NULL,
                        incident_id TEXT NOT NULL,
                        mode TEXT NOT NULL,
                        started_at TEXT NOT NULL,
                        data TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS tool_calls (
                        request_id TEXT PRIMARY KEY,
                        agent_id TEXT NOT NULL,
                        tool_name TEXT NOT NULL,
                        policy_pack TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        data TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS gateway_decisions (
                        request_id TEXT PRIMARY KEY,
                        agent_id TEXT NOT NULL,
                        tool_name TEXT NOT NULL,
                        decision TEXT NOT NULL,
                        tool_executed INTEGER NOT NULL,
                        created_at TEXT NOT NULL,
                        audit_hash TEXT NOT NULL,
                        data TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS permission_evaluations (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        request_id TEXT NOT NULL,
                        agent_id TEXT NOT NULL,
                        tool_name TEXT NOT NULL,
                        permission_state TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        data TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS document_inspections (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        request_id TEXT NOT NULL,
                        document_name TEXT NOT NULL,
                        agent_id TEXT NOT NULL,
                        tool_name TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        data TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS sandbox_notes (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        agent_id TEXT NOT NULL,
                        customer_id TEXT NOT NULL,
                        title TEXT NOT NULL,
                        body TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        data TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS threat_intel_runs (
                        run_id TEXT PRIMARY KEY,
                        title TEXT NOT NULL,
                        source TEXT NOT NULL,
                        policy_pack TEXT NOT NULL,
                        industry TEXT NOT NULL,
                        decision TEXT,
                        blocked_before_execution INTEGER,
                        created_at TEXT NOT NULL,
                        data TEXT NOT NULL
                    );
                    """
                )
            self.available = True
            self.error = None
            return True
        except Exception as exc:  # pragma: no cover - defensive fallback
            self.available = False
            self.error = str(exc)
            return False

    def clear_all(self) -> None:
        if not self.available:
            return
        with self.connection() as connection:
            connection.executescript(
                """
                DELETE FROM runtime_state;
                DELETE FROM agents;
                DELETE FROM incidents;
                DELETE FROM events;
                DELETE FROM human_reviews;
                DELETE FROM audit_reports;
                DELETE FROM audit_bundles;
                DELETE FROM scenario_runs;
                DELETE FROM tool_calls;
                DELETE FROM gateway_decisions;
                DELETE FROM permission_evaluations;
                DELETE FROM document_inspections;
                DELETE FROM sandbox_notes;
                DELETE FROM threat_intel_runs;
                """
            )

    def save_runtime_state(self, snapshot: DashboardSnapshot) -> None:
        if not self.available:
            return
        with self.connection() as connection:
            connection.execute(
                """
                INSERT INTO runtime_state (id, snapshot_json, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    snapshot_json=excluded.snapshot_json,
                    updated_at=excluded.updated_at
                """,
                (
                    "primary",
                    snapshot.model_dump_json(by_alias=True),
                    snapshot.last_updated,
                ),
            )

    def load_runtime_state(self) -> DashboardSnapshot | None:
        if not self.available:
            return None
        with self.connection() as connection:
            row = connection.execute(
                "SELECT snapshot_json FROM runtime_state WHERE id = ?",
                ("primary",),
            ).fetchone()
        if row is None:
            return None
        try:
            return DashboardSnapshot.model_validate_json(row["snapshot_json"])
        except Exception:
            return None
