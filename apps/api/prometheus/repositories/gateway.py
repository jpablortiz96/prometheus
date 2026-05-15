from __future__ import annotations

import json
from datetime import UTC, datetime

from prometheus.models.domain import (
    DocumentInspectResponse,
    PermissionEvaluation,
    ToolCallDecision,
    ToolCallRequest,
)
from prometheus.repositories.database import DatabaseManager


class GatewayRepository:
    def __init__(self, database: DatabaseManager) -> None:
        self.database = database

    def store_tool_call_request(self, request_id: str, request: ToolCallRequest) -> None:
        if not self.database.available:
            return
        with self.database.connection() as connection:
            connection.execute(
                """
                INSERT INTO tool_calls (request_id, agent_id, tool_name, policy_pack, created_at, data)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(request_id) DO UPDATE SET
                    agent_id=excluded.agent_id,
                    tool_name=excluded.tool_name,
                    policy_pack=excluded.policy_pack,
                    created_at=excluded.created_at,
                    data=excluded.data
                """,
                (
                    request_id,
                    request.agent_id,
                    request.tool_name,
                    request.policy_pack,
                    datetime.now(UTC).isoformat(),
                    request.model_dump_json(by_alias=True),
                ),
            )

    def store_permission_evaluation(self, request_id: str, evaluation: PermissionEvaluation) -> None:
        if not self.database.available:
            return
        with self.database.connection() as connection:
            connection.execute(
                """
                INSERT INTO permission_evaluations (
                    request_id,
                    agent_id,
                    tool_name,
                    permission_state,
                    created_at,
                    data
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    request_id,
                    evaluation.agent_id,
                    evaluation.tool_name,
                    evaluation.permission_state,
                    datetime.now(UTC).isoformat(),
                    evaluation.model_dump_json(by_alias=True),
                ),
            )

    def store_decision(self, decision: ToolCallDecision) -> None:
        if not self.database.available:
            return
        with self.database.connection() as connection:
            connection.execute(
                """
                INSERT INTO gateway_decisions (
                    request_id,
                    agent_id,
                    tool_name,
                    decision,
                    tool_executed,
                    created_at,
                    audit_hash,
                    data
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(request_id) DO UPDATE SET
                    agent_id=excluded.agent_id,
                    tool_name=excluded.tool_name,
                    decision=excluded.decision,
                    tool_executed=excluded.tool_executed,
                    created_at=excluded.created_at,
                    audit_hash=excluded.audit_hash,
                    data=excluded.data
                """,
                (
                    decision.request_id,
                    decision.agent_id,
                    decision.tool_name,
                    decision.decision,
                    1 if decision.tool_executed else 0,
                    decision.created_at,
                    decision.audit_hash,
                    decision.model_dump_json(by_alias=True),
                ),
            )

    def list_tool_calls(self, *, limit: int = 20) -> list[ToolCallDecision]:
        if not self.database.available:
            return []
        with self.database.connection() as connection:
            rows = connection.execute(
                """
                SELECT data
                FROM gateway_decisions
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [ToolCallDecision.model_validate(json.loads(row["data"])) for row in rows]

    def get_tool_call(self, request_id: str) -> ToolCallDecision | None:
        if not self.database.available:
            return None
        with self.database.connection() as connection:
            row = connection.execute(
                "SELECT data FROM gateway_decisions WHERE request_id = ?",
                (request_id,),
            ).fetchone()
        if row is None:
            return None
        return ToolCallDecision.model_validate(json.loads(row["data"]))

    def get_tool_call_request(self, request_id: str) -> ToolCallRequest | None:
        if not self.database.available:
            return None
        with self.database.connection() as connection:
            row = connection.execute(
                "SELECT data FROM tool_calls WHERE request_id = ?",
                (request_id,),
            ).fetchone()
        if row is None:
            return None
        return ToolCallRequest.model_validate(json.loads(row["data"]))

    def store_document_inspection(self, response: DocumentInspectResponse) -> None:
        if not self.database.available:
            return
        with self.database.connection() as connection:
            connection.execute(
                """
                INSERT INTO document_inspections (
                    request_id,
                    document_name,
                    agent_id,
                    tool_name,
                    created_at,
                    data
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    response.tool_decision.request_id,
                    response.document_name,
                    response.tool_decision.agent_id,
                    response.tool_decision.tool_name,
                    datetime.now(UTC).isoformat(),
                    response.model_dump_json(by_alias=True),
                ),
            )
