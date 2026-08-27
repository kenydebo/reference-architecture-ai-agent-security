"""
Tool broker: the enforcement boundary.

The agent never reaches an enterprise system directly. It asks the broker, and
the broker decides. Every consequential step is recorded as security evidence
at the moment the decision is made, by the broker rather than by the agent, so
a hijacked agent cannot suppress the record of its own denied request.

Order of enforcement for every invocation:

    validate credential (session-bound)   -> identity.validation_{succeeded,failed}
    record the request                    -> agent.tool_requested
    authorize                             -> policy.decision
    deny  -> record and raise an incident -> tool.execution_denied
                                             security.incident_created
    allow -> execute                      -> tool.execution_started
             screen output for sensitive     dlp.detection
             identifiers                     tool.execution_completed
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from forensics.evidence import EvidenceLedger
from gateway.authorization import AuthorizationEngine, Decision, RESOURCE_CATALOG
from gateway.detection import redact, scan_tool_output
from gateway.identity import IdentityError, IdentityProvider

INCIDENT_YEAR = 2026


@dataclass
class ToolResult:
    status: str  # "completed" | "denied" | "identity_rejected"
    tool: str
    output: str | None = None
    policy_id: str | None = None
    reason: str | None = None
    incident_id: str | None = None
    decision: Decision | None = None
    dlp_findings: list[dict] = field(default_factory=list)
    redacted: bool = False


def _clinical_search(args: dict) -> str:
    return (
        "3 study records matched in the synthetic corpus: "
        "BW-101 (phase II, complete), BW-207 (phase I, recruiting), "
        "BW-214 (phase II, complete)."
    )


def _documents_summarize(args: dict) -> str:
    # The repository stub deliberately returns a document excerpt carrying a
    # synthetic identifier, so the output-screening control has a live path.
    return (
        "Summary of R&D repository documents: cohort enrollment steady across "
        "sites; adverse-event rate within expected range. Source excerpt notes "
        "follow-up scheduled for MRN-4471902 at the coordinating site."
    )


def _erp_query(args: dict) -> str:
    return "ERP: 4 open purchase orders, none flagged for review."


def _manufacturing_status(args: dict) -> str:
    return "Manufacturing: 2 lines running, 0 deviations open."


def _clinical_data_export(args: dict) -> str:
    # Never reached in this project: authorization denies it on every path.
    # Present so the resource exists and can be legitimately requested.
    return "RESTRICTED EXPORT PAYLOAD"


TOOL_IMPLEMENTATIONS: dict[str, Callable[[dict], str]] = {
    "clinical.search": _clinical_search,
    "documents.summarize": _documents_summarize,
    "erp.query": _erp_query,
    "manufacturing.status": _manufacturing_status,
    "clinical_data.export": _clinical_data_export,
}


class ToolBroker:
    """Mediates every agent-to-tool action and records the decision."""

    def __init__(
        self,
        ledger: EvidenceLedger,
        identity_provider: IdentityProvider,
        authorizer: AuthorizationEngine | None = None,
    ):
        self.ledger = ledger
        self.identity = identity_provider
        self.authorizer = authorizer or AuthorizationEngine()

    def _next_incident_id(self) -> str:
        existing = sum(
            1 for e in self.ledger.entries() if e["event_type"] == "security.incident_created"
        )
        return f"AI-{INCIDENT_YEAR}-{existing + 1:04d}"

    def invoke(
        self,
        session_id: str,
        credential: str,
        tool: str,
        purpose: str,
        args: dict[str, Any] | None = None,
    ) -> ToolResult:
        args = args or {}

        # --- 1. Identity -------------------------------------------------
        try:
            claims = self.identity.validate(credential, session_id)
        except IdentityError as exc:
            # A rejected credential is a security event. It must never fail
            # silently: the absence of a record is indistinguishable from the
            # absence of an attempt.
            self.ledger.append(
                session_id,
                "identity.validation_failed",
                {"component": "gateway.identity"},
                {"reason": exc.reason, "detail": exc.message, "requested_tool": tool},
            )
            incident_id = self._raise_incident(
                session_id,
                tool=tool,
                severity="MEDIUM",
                title="Agent presented a credential that failed validation",
                detail={"identity_failure_reason": exc.reason},
            )
            return ToolResult(
                status="identity_rejected",
                tool=tool,
                reason=exc.message,
                incident_id=incident_id,
            )

        self.ledger.append(
            session_id,
            "identity.validation_succeeded",
            {"component": "gateway.identity"},
            {
                "agent_id": claims["agent_id"],
                "spiffe_id": claims["sub"],
                "role": claims["role"],
                "session_bound": True,
                "credential_scope": claims["scope"],
            },
        )

        # --- 2. Record the request --------------------------------------
        self.ledger.append(
            session_id,
            "agent.tool_requested",
            {"agent": claims["agent_id"]},
            {"tool": tool, "purpose": purpose, "args": args},
        )

        # --- 3. Authorize ------------------------------------------------
        decision = self.authorizer.evaluate(claims, tool, purpose)
        resource = RESOURCE_CATALOG.get(tool, {"system": "unknown", "classification": "unknown"})
        self.ledger.append(
            session_id,
            "policy.decision",
            {"component": "gateway.authorization"},
            {
                "tool": tool,
                "decision": "ALLOW" if decision.allowed else "DENY",
                "policy_id": decision.policy_id,
                "reason": decision.reason,
                "resource_system": resource["system"],
                "resource_classification": resource["classification"],
                "matched_deny_policies": [
                    {"policy_id": d.policy_id, "control": d.control, "reason": d.reason}
                    for d in decision.deny_reasons
                ],
                "evaluation_input": decision.evaluation_input,
            },
        )

        # --- 4. Deny path -------------------------------------------------
        if not decision.allowed:
            self.ledger.append(
                session_id,
                "tool.execution_denied",
                {"component": "gateway.tool_broker"},
                {
                    "tool": tool,
                    "policy_id": decision.policy_id,
                    "resource_classification": resource["classification"],
                },
            )
            incident_id = self._raise_incident(
                session_id,
                tool=tool,
                severity=None,
                title=None,
                detail={
                    "policy_id": decision.policy_id,
                    "matched_deny_policies": decision.matched_policy_ids,
                    "resource_classification": resource["classification"],
                },
            )
            return ToolResult(
                status="denied",
                tool=tool,
                policy_id=decision.policy_id,
                reason=decision.reason,
                incident_id=incident_id,
                decision=decision,
            )

        # --- 5. Allow path ------------------------------------------------
        self.ledger.append(
            session_id,
            "tool.execution_started",
            {"agent": claims["agent_id"]},
            {"tool": tool, "resource_system": resource["system"]},
        )
        output = TOOL_IMPLEMENTATIONS[tool](args)

        dlp_findings = scan_tool_output(output)
        redacted = False
        if dlp_findings:
            output = redact(output)
            redacted = True
            self.ledger.append(
                session_id,
                "dlp.detection",
                {"component": "gateway.detection"},
                {
                    "tool": tool,
                    "action": "redacted",
                    "finding_count": len(dlp_findings),
                    "findings": dlp_findings,
                },
            )

        self.ledger.append(
            session_id,
            "tool.execution_completed",
            {"agent": claims["agent_id"]},
            {"tool": tool, "output_chars": len(output), "output_redacted": redacted},
        )
        return ToolResult(
            status="completed",
            tool=tool,
            output=output,
            policy_id=decision.policy_id,
            reason=decision.reason,
            decision=decision,
            dlp_findings=dlp_findings,
            redacted=redacted,
        )

    def _raise_incident(
        self,
        session_id: str,
        tool: str,
        severity: str | None,
        title: str | None,
        detail: dict,
    ) -> str:
        """Create a security incident linked to this session's evidence."""
        events = self.ledger.session(session_id)
        injection_events = [
            e for e in events if e["event_type"] == "detection.injection_indicator"
        ]
        if severity is None:
            severity = "HIGH" if injection_events else "MEDIUM"
        if title is None:
            title = (
                "Agent attempted a restricted action after retrieving untrusted "
                "content containing injection indicators"
                if injection_events
                else "Agent attempted an action outside its authorized capabilities"
            )

        incident_id = self._next_incident_id()
        self.ledger.append(
            session_id,
            "security.incident_created",
            {"component": "gateway.detection"},
            {
                "incident_id": incident_id,
                "severity": severity,
                "title": title,
                "denied_tool": tool,
                "related_injection_events": [e["event_id"] for e in injection_events],
                **detail,
            },
        )
        return incident_id
