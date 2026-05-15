from __future__ import annotations

import json

from prometheus.models.domain import AuditBundleResponse, AuditReportArchiveItem, AuditReportExport
from prometheus.repositories.database import DatabaseManager


class ReportsRepository:
    def __init__(self, database: DatabaseManager) -> None:
        self.database = database

    def store_bundle(self, bundle: AuditBundleResponse, *, model_used: str) -> None:
        if not self.database.available:
            return
        with self.database.connection() as connection:
            connection.execute(
                """
                INSERT INTO audit_reports (
                    incident_id,
                    title,
                    generated_at,
                    format,
                    decision,
                    policy_pack,
                    audit_hash,
                    model_used,
                    data
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    bundle.incident_id,
                    f"{bundle.incident_id} Audit Bundle",
                    bundle.generated_at,
                    "bundle",
                    bundle.decision,
                    bundle.policy_pack,
                    bundle.audit_hash,
                    model_used,
                    bundle.model_dump_json(by_alias=True),
                ),
            )
            connection.execute(
                """
                INSERT INTO audit_bundles (incident_id, generated_at, audit_hash, data)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(incident_id) DO UPDATE SET
                    generated_at=excluded.generated_at,
                    audit_hash=excluded.audit_hash,
                    data=excluded.data
                """,
                (
                    bundle.incident_id,
                    bundle.generated_at,
                    bundle.audit_hash,
                    bundle.model_dump_json(by_alias=True),
                ),
            )

    def store_export(
        self,
        export: AuditReportExport,
        *,
        incident_id: str,
        decision: str,
        policy_pack: str,
        audit_hash: str,
    ) -> None:
        if not self.database.available:
            return
        with self.database.connection() as connection:
            connection.execute(
                """
                INSERT INTO audit_reports (
                    incident_id,
                    title,
                    generated_at,
                    format,
                    decision,
                    policy_pack,
                    audit_hash,
                    model_used,
                    data
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    incident_id,
                    export.title,
                    export.generated_at,
                    export.format,
                    decision,
                    policy_pack,
                    audit_hash,
                    export.model_used,
                    export.model_dump_json(by_alias=True),
                ),
            )

    def list_reports(self, *, limit: int = 50) -> list[AuditReportArchiveItem]:
        if not self.database.available:
            return []
        with self.database.connection() as connection:
            rows = connection.execute(
                """
                SELECT incident_id, title, generated_at, format, decision, policy_pack, audit_hash, model_used
                FROM audit_reports
                ORDER BY generated_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [
            AuditReportArchiveItem(
                incident_id=row["incident_id"],
                title=row["title"],
                generated_at=row["generated_at"],
                format=row["format"],
                decision=row["decision"],
                policy_pack=row["policy_pack"],
                audit_hash=row["audit_hash"],
                model_used=row["model_used"],
            )
            for row in rows
        ]

    def reports_for_incident(self, incident_id: str) -> list[AuditReportArchiveItem]:
        if not self.database.available:
            return []
        with self.database.connection() as connection:
            rows = connection.execute(
                """
                SELECT incident_id, title, generated_at, format, decision, policy_pack, audit_hash, model_used
                FROM audit_reports
                WHERE incident_id = ?
                ORDER BY generated_at DESC
                """,
                (incident_id,),
            ).fetchall()
        return [
            AuditReportArchiveItem(
                incident_id=row["incident_id"],
                title=row["title"],
                generated_at=row["generated_at"],
                format=row["format"],
                decision=row["decision"],
                policy_pack=row["policy_pack"],
                audit_hash=row["audit_hash"],
                model_used=row["model_used"],
            )
            for row in rows
        ]

    def latest_bundle(self, incident_id: str) -> AuditBundleResponse | None:
        if not self.database.available:
            return None
        with self.database.connection() as connection:
            row = connection.execute(
                """
                SELECT data
                FROM audit_bundles
                WHERE incident_id = ?
                """,
                (incident_id,),
            ).fetchone()
        if row is None:
            return None
        return AuditBundleResponse.model_validate(json.loads(row["data"]))
