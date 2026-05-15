from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from prometheus.models.domain import SandboxToolResult
from prometheus.repositories.database import DatabaseManager


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    data_classification: str
    external_egress: bool
    default_permission_state: str


class SandboxToolsService:
    def __init__(self, database: DatabaseManager) -> None:
        self.database = database
        self._notes_fallback: list[dict[str, Any]] = []
        self._tool_specs = {
            "crm.query": ToolSpec(
                name="crm.query",
                description="Read-only CRM intelligence query.",
                data_classification="customer_confidential",
                external_egress=False,
                default_permission_state="allowed",
            ),
            "crm.note": ToolSpec(
                name="crm.note",
                description="Write a CRM note into the local audit store.",
                data_classification="customer_confidential",
                external_egress=False,
                default_permission_state="allowed",
            ),
            "crm.export": ToolSpec(
                name="crm.export",
                description="Bulk CRM export to an external destination.",
                data_classification="customer_confidential",
                external_egress=True,
                default_permission_state="quarantine",
            ),
            "email.send_external": ToolSpec(
                name="email.send_external",
                description="Simulated outbound email to an external address.",
                data_classification="restricted",
                external_egress=True,
                default_permission_state="denied",
            ),
            "finance.read": ToolSpec(
                name="finance.read",
                description="Read-only access to summary finance data.",
                data_classification="regulated_finance",
                external_egress=False,
                default_permission_state="allowed",
            ),
            "finance.export_external": ToolSpec(
                name="finance.export_external",
                description="Simulated finance export to an external destination.",
                data_classification="regulated_finance",
                external_egress=True,
                default_permission_state="quarantine",
            ),
            "ledger.reconcile": ToolSpec(
                name="ledger.reconcile",
                description="Read-only reconciliation workflow.",
                data_classification="regulated_finance",
                external_egress=False,
                default_permission_state="allowed",
            ),
            "contracts.rewrite": ToolSpec(
                name="contracts.rewrite",
                description="Apply a simulated contract clause rewrite.",
                data_classification="legal_privileged",
                external_egress=False,
                default_permission_state="human_review",
            ),
            "docs.index": ToolSpec(
                name="docs.index",
                description="Index a document into the local knowledge store.",
                data_classification="internal",
                external_egress=False,
                default_permission_state="allowed",
            ),
            "docs.read": ToolSpec(
                name="docs.read",
                description="Read a document excerpt.",
                data_classification="internal",
                external_egress=False,
                default_permission_state="allowed",
            ),
            "refund.execute": ToolSpec(
                name="refund.execute",
                description="Execute a simulated customer refund.",
                data_classification="regulated_finance",
                external_egress=False,
                default_permission_state="human_review",
            ),
            "hr.records.export": ToolSpec(
                name="hr.records.export",
                description="Bulk HR records export.",
                data_classification="hr_restricted",
                external_egress=True,
                default_permission_state="quarantine",
            ),
            "vuln.research": ToolSpec(
                name="vuln.research",
                description="Synthetic defensive vulnerability research inside a sandbox.",
                data_classification="security_internal",
                external_egress=False,
                default_permission_state="allowed",
            ),
            "report.write": ToolSpec(
                name="report.write",
                description="Write a defensive security summary into the local audit store.",
                data_classification="security_internal",
                external_egress=False,
                default_permission_state="allowed",
            ),
            "scanner.run": ToolSpec(
                name="scanner.run",
                description="Run a synthetic scanner only after human review.",
                data_classification="security_internal",
                external_egress=False,
                default_permission_state="human_review",
            ),
            "exploit.generate": ToolSpec(
                name="exploit.generate",
                description="Prohibited exploit-generation workflow.",
                data_classification="security_restricted",
                external_egress=False,
                default_permission_state="denied",
            ),
            "exploit.execute": ToolSpec(
                name="exploit.execute",
                description="Prohibited exploit-execution workflow.",
                data_classification="security_restricted",
                external_egress=False,
                default_permission_state="denied",
            ),
            "auth.bypass_test": ToolSpec(
                name="auth.bypass_test",
                description="High-risk authentication bypass testing workflow.",
                data_classification="security_restricted",
                external_egress=False,
                default_permission_state="quarantine",
            ),
        }

    def catalog(self) -> list[ToolSpec]:
        return list(self._tool_specs.values())

    def get_spec(self, tool_name: str) -> ToolSpec:
        spec = self._tool_specs.get(tool_name)
        if spec is None:
            raise KeyError(f"Unknown sandbox tool: {tool_name}")
        return spec

    def execute(
        self,
        *,
        agent_id: str,
        tool_name: str,
        payload: dict[str, Any],
    ) -> SandboxToolResult:
        spec = self.get_spec(tool_name)
        handler_name = tool_name.replace(".", "_")
        handler = getattr(self, f"_execute_{handler_name}", None)
        if handler is None:
            raise KeyError(f"Tool handler not implemented: {tool_name}")
        result, side_effect_summary = handler(agent_id=agent_id, payload=payload)
        return SandboxToolResult(
            tool_name=tool_name,
            executed=True,
            result=result,
            side_effect_summary=side_effect_summary,
            data_classification=spec.data_classification,
        )

    def _execute_crm_query(
        self,
        *,
        agent_id: str,
        payload: dict[str, Any],
    ) -> tuple[dict[str, Any], str]:
        query = str(payload.get("query") or "top renewal accounts")
        accounts = [
            {"customer": "Northwind Health", "segment": "enterprise", "renewal_risk": "low"},
            {"customer": "Atlas Retail", "segment": "mid-market", "renewal_risk": "watch"},
            {"customer": "Mercury Logistics", "segment": "enterprise", "renewal_risk": "high"},
        ]
        return (
            {"query": query, "records": accounts, "recordCount": len(accounts), "agentId": agent_id},
            "Read-only CRM intelligence query returned 3 synthetic accounts.",
        )

    def _execute_crm_note(
        self,
        *,
        agent_id: str,
        payload: dict[str, Any],
    ) -> tuple[dict[str, Any], str]:
        note = {
            "agent_id": agent_id,
            "customer_id": payload.get("customer_id", "acct_demo_001"),
            "title": payload.get("title", "Prometheus note"),
            "body": payload.get("body", "Synthetic CRM note"),
            "created_at": datetime.now(UTC).isoformat(),
        }
        if self.database.available:
            with self.database.connection() as connection:
                connection.execute(
                    """
                    INSERT INTO sandbox_notes (agent_id, customer_id, title, body, created_at, data)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        note["agent_id"],
                        note["customer_id"],
                        note["title"],
                        note["body"],
                        note["created_at"],
                        json.dumps(note, sort_keys=True),
                    ),
                )
        else:
            self._notes_fallback.append(note)
        return (
            {"noteId": f"note_{len(self._notes_fallback) + 1}", "stored": True},
            "CRM note persisted into the local Prometheus audit store.",
        )

    def _execute_crm_export(
        self,
        *,
        agent_id: str,
        payload: dict[str, Any],
    ) -> tuple[dict[str, Any], str]:
        destination = payload.get("destination", "approved-vault")
        return (
            {"exportId": f"crm_export_{agent_id}", "destination": destination, "rows": 24},
            "Synthetic CRM export bundle generated for the approved destination.",
        )

    def _execute_email_send_external(
        self,
        *,
        agent_id: str,
        payload: dict[str, Any],
    ) -> tuple[dict[str, Any], str]:
        recipient = payload.get("to", "external@example.com")
        return (
            {"messageId": f"mail_{agent_id}", "to": recipient, "queued": True},
            "No real email was sent. A simulated outbound email was queued in the sandbox.",
        )

    def _execute_finance_read(
        self,
        *,
        agent_id: str,
        payload: dict[str, Any],
    ) -> tuple[dict[str, Any], str]:
        report_name = payload.get("report_name", "quarterly_summary")
        return (
            {
                "agentId": agent_id,
                "reportName": report_name,
                "revenue": 1284000,
                "variance": -0.012,
                "currency": "USD",
            },
            "Read-only finance summary returned from the sandbox ledger.",
        )

    def _execute_finance_export_external(
        self,
        *,
        agent_id: str,
        payload: dict[str, Any],
    ) -> tuple[dict[str, Any], str]:
        destination = payload.get("destination", "approved-board-room")
        return (
            {"exportId": f"fin_export_{agent_id}", "destination": destination, "rows": 12},
            "Synthetic finance export bundle created. No real enterprise ledger was touched.",
        )

    def _execute_ledger_reconcile(
        self,
        *,
        agent_id: str,
        payload: dict[str, Any],
    ) -> tuple[dict[str, Any], str]:
        invoice_batch = payload.get("batch", "batch_042")
        return (
            {"batch": invoice_batch, "varianceFound": False, "recordsChecked": 42, "agentId": agent_id},
            "Sandbox ledger reconciliation completed without side effects outside the local store.",
        )

    def _execute_contracts_rewrite(
        self,
        *,
        agent_id: str,
        payload: dict[str, Any],
    ) -> tuple[dict[str, Any], str]:
        clause = payload.get("clause", "liability")
        rewrite = payload.get("rewrite", "Liability limited to direct damages only.")
        return (
            {"agentId": agent_id, "clause": clause, "rewrite": rewrite, "redlineId": f"redline_{agent_id}"},
            "Sandbox contract rewrite generated a simulated redline for human review.",
        )

    def _execute_docs_index(
        self,
        *,
        agent_id: str,
        payload: dict[str, Any],
    ) -> tuple[dict[str, Any], str]:
        document_name = payload.get("document_name", "document.md")
        content = str(payload.get("content", ""))
        chunks = max(1, len(content.split()) // 80 or 1)
        return (
            {"agentId": agent_id, "documentName": document_name, "chunksIndexed": chunks},
            "Document indexed into the sandbox knowledge store with no external side effects.",
        )

    def _execute_docs_read(
        self,
        *,
        agent_id: str,
        payload: dict[str, Any],
    ) -> tuple[dict[str, Any], str]:
        content = str(payload.get("content", ""))
        excerpt = content[:180] if content else "Synthetic document excerpt."
        return (
            {"agentId": agent_id, "excerpt": excerpt, "length": len(content)},
            "Document excerpt retrieved from the sandbox store.",
        )

    def _execute_refund_execute(
        self,
        *,
        agent_id: str,
        payload: dict[str, Any],
    ) -> tuple[dict[str, Any], str]:
        amount = float(payload.get("amount", 0))
        customer_id = payload.get("customer_id", "cust_demo_001")
        return (
            {"refundId": f"refund_{agent_id}", "customerId": customer_id, "amount": amount, "status": "approved"},
            "Refund executed only inside the sandbox ledger. No real payment rail was touched.",
        )

    def _execute_hr_records_export(
        self,
        *,
        agent_id: str,
        payload: dict[str, Any],
    ) -> tuple[dict[str, Any], str]:
        destination = payload.get("destination", "approved-hr-vault")
        return (
            {"exportId": f"hr_export_{agent_id}", "destination": destination, "records": 18},
            "Synthetic HR export package assembled for the sandbox destination only.",
        )

    def _execute_vuln_research(
        self,
        *,
        agent_id: str,
        payload: dict[str, Any],
    ) -> tuple[dict[str, Any], str]:
        topic = str(payload.get("topic") or payload.get("report_title") or "emerging threat report")
        return (
            {
                "agentId": agent_id,
                "topic": topic,
                "summary": "Synthetic defensive research only. No exploit detail generated.",
                "recommendedControls": [
                    "block exploit generation",
                    "require review for scanners",
                    "quarantine identity bypass testing",
                ],
            },
            "Defensive vulnerability research completed in the sandbox with no live target interaction.",
        )

    def _execute_report_write(
        self,
        *,
        agent_id: str,
        payload: dict[str, Any],
    ) -> tuple[dict[str, Any], str]:
        title = str(payload.get("title") or payload.get("report_title") or "Zero-Day Sentinel brief")
        note_payload = {
            "customer_id": "security_program",
            "title": title,
            "body": str(payload.get("summary") or payload.get("content") or "Defensive report written."),
        }
        result, _ = self._execute_crm_note(agent_id=agent_id, payload=note_payload)
        return (
            {
                "reportId": result["noteId"],
                "title": title,
                "status": "stored",
            },
            "Defensive security summary persisted into the local audit store.",
        )

    def _execute_scanner_run(
        self,
        *,
        agent_id: str,
        payload: dict[str, Any],
    ) -> tuple[dict[str, Any], str]:
        target = str(payload.get("target") or "synthetic-lab-host")
        return (
            {
                "agentId": agent_id,
                "target": target,
                "mode": "synthetic_only",
                "findings": [
                    "Patch validation pending human review.",
                    "No real network activity executed.",
                ],
            },
            "Synthetic scanner simulation produced a defensive placeholder only after review control.",
        )

    def _execute_exploit_generate(
        self,
        *,
        agent_id: str,
        payload: dict[str, Any],
    ) -> tuple[dict[str, Any], str]:
        return (
            {
                "agentId": agent_id,
                "status": "refused",
                "message": "No exploit code is ever generated in the sandbox.",
            },
            "Exploit generation remained a synthetic placeholder. No code or payloads were created.",
        )

    def _execute_exploit_execute(
        self,
        *,
        agent_id: str,
        payload: dict[str, Any],
    ) -> tuple[dict[str, Any], str]:
        return (
            {
                "agentId": agent_id,
                "status": "refused",
                "message": "No exploit execution is ever performed in the sandbox.",
            },
            "Exploit execution remained a synthetic placeholder. No target interaction occurred.",
        )

    def _execute_auth_bypass_test(
        self,
        *,
        agent_id: str,
        payload: dict[str, Any],
    ) -> tuple[dict[str, Any], str]:
        return (
            {
                "agentId": agent_id,
                "status": "quarantined",
                "message": "Authentication bypass testing is simulated only and never touches a real identity system.",
            },
            "Authentication bypass testing remained quarantined inside the sandbox with no real identity traffic.",
        )
