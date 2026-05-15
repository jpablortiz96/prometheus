from __future__ import annotations

import json
from typing import Any

from prometheus.models.domain import ThreatIntelRunResult, ThreatIntelRunSummary
from prometheus.repositories.database import DatabaseManager


class ThreatIntelRepository:
    def __init__(self, database: DatabaseManager) -> None:
        self.database = database

    def store_run(self, result: ThreatIntelRunResult) -> None:
        if not self.database.available:
            return
        with self.database.connection() as connection:
            connection.execute(
                """
                INSERT INTO threat_intel_runs (
                    run_id,
                    title,
                    source,
                    policy_pack,
                    industry,
                    decision,
                    blocked_before_execution,
                    created_at,
                    data
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(run_id) DO UPDATE SET
                    title=excluded.title,
                    source=excluded.source,
                    policy_pack=excluded.policy_pack,
                    industry=excluded.industry,
                    decision=excluded.decision,
                    blocked_before_execution=excluded.blocked_before_execution,
                    created_at=excluded.created_at,
                    data=excluded.data
                """,
                (
                    result.run_id,
                    result.title,
                    result.source,
                    result.policy_pack,
                    result.industry,
                    result.gateway_decision.decision if result.gateway_decision else None,
                    1 if result.blocked_before_execution else 0 if result.blocked_before_execution is not None else None,
                    result.created_at,
                    result.model_dump_json(by_alias=True),
                ),
            )

    def list_runs(self, *, limit: int = 20) -> list[ThreatIntelRunSummary]:
        if not self.database.available:
            return []
        with self.database.connection() as connection:
            rows = connection.execute(
                """
                SELECT run_id, title, source, policy_pack, industry, decision, blocked_before_execution, created_at, data
                FROM threat_intel_runs
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        summaries: list[ThreatIntelRunSummary] = []
        for row in rows:
            payload = self._load_payload(row["data"])
            gateway_decision = payload.get("gatewayDecision") or {}
            generated_scenario = payload.get("generatedScenario") or {}
            audit_bundle = payload.get("auditBundle") or {}
            summaries.append(
                ThreatIntelRunSummary(
                    run_id=row["run_id"],
                    title=row["title"],
                    source=row["source"],
                    policy_pack=row["policy_pack"],
                    industry=row["industry"],
                    decision=row["decision"],
                    attempted_tool=generated_scenario.get("attemptedTool")
                    or gateway_decision.get("toolName"),
                    tool_executed=gateway_decision.get("toolExecuted"),
                    incident_id=audit_bundle.get("incidentId")
                    or gateway_decision.get("sourceEventId"),
                    blocked_before_execution=None
                    if row["blocked_before_execution"] is None
                    else bool(row["blocked_before_execution"]),
                    created_at=row["created_at"],
                )
            )
        return summaries

    def get_run(self, run_id: str) -> ThreatIntelRunResult | None:
        if not self.database.available:
            return None
        with self.database.connection() as connection:
            row = connection.execute(
                "SELECT data FROM threat_intel_runs WHERE run_id = ?",
                (run_id,),
            ).fetchone()
        if row is None:
            return None
        return ThreatIntelRunResult.model_validate(json.loads(row["data"]))

    def _load_payload(self, raw: str) -> dict[str, Any]:
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            return {}
        if isinstance(payload, dict):
            return payload
        return {}
