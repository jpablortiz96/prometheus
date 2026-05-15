from __future__ import annotations

import json
from datetime import UTC, datetime

from prometheus.models.domain import AgentRecord, EventRecord
from prometheus.repositories.database import DatabaseManager


class EventsRepository:
    def __init__(self, database: DatabaseManager) -> None:
        self.database = database

    def upsert_agents(self, agents: list[AgentRecord]) -> None:
        if not self.database.available:
            return
        rows = [
            (
                agent.id,
                agent.status,
                agent.trust_score,
                agent.policy_pack,
                datetime.now(UTC).isoformat(),
                agent.model_dump_json(by_alias=True),
            )
            for agent in agents
        ]
        with self.database.connection() as connection:
            connection.executemany(
                """
                INSERT INTO agents (id, status, trust_score, policy_pack, updated_at, data)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    status=excluded.status,
                    trust_score=excluded.trust_score,
                    policy_pack=excluded.policy_pack,
                    updated_at=excluded.updated_at,
                    data=excluded.data
                """,
                rows,
            )

    def list_agents(self) -> list[AgentRecord]:
        if not self.database.available:
            return []
        with self.database.connection() as connection:
            rows = connection.execute(
                "SELECT data FROM agents ORDER BY id ASC"
            ).fetchall()
        return [AgentRecord.model_validate(json.loads(row["data"])) for row in rows]

    def upsert_events(self, events: list[EventRecord]) -> None:
        if not self.database.available:
            return
        rows = [
            (
                event.id,
                event.id,
                event.scenario_id,
                event.agent_id,
                event.decision,
                event.severity,
                event.review_status,
                event.timestamp,
                event.model_dump_json(by_alias=True),
            )
            for event in events
        ]
        with self.database.connection() as connection:
            connection.executemany(
                """
                INSERT INTO events (
                    event_id,
                    incident_id,
                    scenario_id,
                    agent_id,
                    decision,
                    severity,
                    review_status,
                    timestamp,
                    data
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(event_id) DO UPDATE SET
                    incident_id=excluded.incident_id,
                    scenario_id=excluded.scenario_id,
                    agent_id=excluded.agent_id,
                    decision=excluded.decision,
                    severity=excluded.severity,
                    review_status=excluded.review_status,
                    timestamp=excluded.timestamp,
                    data=excluded.data
                """,
                rows,
            )

    def list_recent_events(self, *, limit: int = 18) -> list[EventRecord]:
        if not self.database.available:
            return []
        with self.database.connection() as connection:
            rows = connection.execute(
                "SELECT data FROM events ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [EventRecord.model_validate(json.loads(row["data"])) for row in rows]

    def get_event(self, event_id: str) -> EventRecord | None:
        if not self.database.available:
            return None
        with self.database.connection() as connection:
            row = connection.execute(
                "SELECT data FROM events WHERE event_id = ?",
                (event_id,),
            ).fetchone()
        if row is None:
            return None
        return EventRecord.model_validate(json.loads(row["data"]))

    def record_scenario_run(
        self,
        *,
        scenario_id: str,
        incident_id: str,
        mode: str,
        data: dict[str, object],
    ) -> None:
        if not self.database.available:
            return
        with self.database.connection() as connection:
            connection.execute(
                """
                INSERT INTO scenario_runs (scenario_id, incident_id, mode, started_at, data)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    scenario_id,
                    incident_id,
                    mode,
                    datetime.now(UTC).isoformat(),
                    json.dumps(data, sort_keys=True),
                ),
            )
