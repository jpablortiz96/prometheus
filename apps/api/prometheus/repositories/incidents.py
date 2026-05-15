from __future__ import annotations

import json
from datetime import UTC, datetime

from prometheus.models.domain import EventRecord, IncidentCommandCenter, IncidentSummary
from prometheus.repositories.database import DatabaseManager


def incident_from_event(event: EventRecord) -> IncidentCommandCenter:
    return IncidentCommandCenter(
        incident_id=event.id,
        severity=event.severity,
        affected_agent=event.agent_id,
        declared_intent=event.declared_intent,
        detected_intent=event.detected_intent,
        predicted_action=event.predicted_action,
        observed_action=event.observed_action,
        policy_matched=event.evidence.matched_policy_rules,
        final_decision=event.decision,
        decision_label=event.decision_label,
        business_impact=event.impact.business_impact,
        regulatory_impact=event.impact.regulatory_impact,
        department=event.impact.department,
        compliance_concern=event.impact.compliance_concern,
        risk_score=event.risk_score,
        trust_delta=event.evidence.trust_delta,
    )


class IncidentsRepository:
    def __init__(self, database: DatabaseManager) -> None:
        self.database = database

    def upsert_from_events(self, events: list[EventRecord]) -> None:
        if not self.database.available:
            return
        rows = []
        for event in events:
            incident = incident_from_event(event)
            rows.append(
                (
                    incident.incident_id,
                    event.id,
                    event.scenario_id,
                    event.agent_id,
                    event.decision,
                    event.severity,
                    event.risk_score,
                    event.policy_pack,
                    event.timestamp,
                    incident.model_dump_json(by_alias=True),
                )
            )

        with self.database.connection() as connection:
            connection.executemany(
                """
                INSERT INTO incidents (
                    incident_id,
                    event_id,
                    scenario_id,
                    agent_id,
                    decision,
                    severity,
                    risk_score,
                    policy_pack,
                    created_at,
                    data
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(incident_id) DO UPDATE SET
                    event_id=excluded.event_id,
                    scenario_id=excluded.scenario_id,
                    agent_id=excluded.agent_id,
                    decision=excluded.decision,
                    severity=excluded.severity,
                    risk_score=excluded.risk_score,
                    policy_pack=excluded.policy_pack,
                    created_at=excluded.created_at,
                    data=excluded.data
                """,
                rows,
            )

    def list_incidents(self, *, limit: int = 50) -> list[IncidentSummary]:
        if not self.database.available:
            return []
        with self.database.connection() as connection:
            rows = connection.execute(
                """
                SELECT
                    incidents.incident_id,
                    incidents.agent_id,
                    incidents.severity,
                    incidents.decision,
                    incidents.risk_score,
                    incidents.policy_pack,
                    incidents.created_at,
                    events.data AS event_data
                FROM incidents
                LEFT JOIN events ON events.event_id = incidents.event_id
                ORDER BY incidents.created_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        incidents: list[IncidentSummary] = []
        for row in rows:
            event_payload = json.loads(row["event_data"]) if row["event_data"] else None
            title = event_payload["title"] if event_payload else row["incident_id"]
            decision_label = event_payload["decisionLabel"] if event_payload else row["decision"]
            incidents.append(
                IncidentSummary(
                    incident_id=row["incident_id"],
                    title=title,
                    agent_id=row["agent_id"],
                    severity=row["severity"],
                    decision=row["decision"],
                    decision_label=decision_label,
                    policy_pack=row["policy_pack"],
                    risk_score=row["risk_score"],
                    timestamp=row["created_at"],
                )
            )
        return incidents

    def get_incident(self, incident_id: str) -> IncidentCommandCenter | None:
        if not self.database.available:
            return None
        with self.database.connection() as connection:
            row = connection.execute(
                "SELECT data FROM incidents WHERE incident_id = ?",
                (incident_id,),
            ).fetchone()
        if row is None:
            return None
        return IncidentCommandCenter.model_validate(json.loads(row["data"]))

    def record_human_review(
        self,
        *,
        event_id: str,
        incident_id: str,
        action: str,
        message: str,
        data: dict[str, object],
    ) -> None:
        if not self.database.available:
            return
        with self.database.connection() as connection:
            connection.execute(
                """
                INSERT INTO human_reviews (event_id, incident_id, action, message, created_at, data)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    incident_id,
                    action,
                    message,
                    datetime.now(UTC).isoformat(),
                    json.dumps(data, sort_keys=True),
                ),
            )
