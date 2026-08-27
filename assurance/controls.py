"""
Evidence-based security control validation.

The claim this module makes is narrow and precise:

    Security-control assertions can be validated against actual runtime
    evidence rather than manually asserted.

It is not a regulatory audit platform and does not claim to be one.

Each control carries a predicate that inspects the specific evidence relevant
to that control. A generic denial does not satisfy a specific control: the
restricted-data control requires a denial of the export action against a
PHI-classified resource, not merely that something, somewhere, was denied.

Three outcomes are distinguished, because conflating them is how assurance
reporting becomes misleading:

    PASS        the control was exercised and behaved correctly
    FAIL        the control was exercised and did not behave correctly
    NOT_TESTED  the conditions that exercise this control did not occur

A control that was never exercised is not a passing control.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from forensics.evidence import EvidenceLedger, verify_ledger

PASS = "PASS"
FAIL = "FAIL"
NOT_TESTED = "NOT_TESTED"

EXPORT_TOOL = "clinical_data.export"
PHI_CLASSIFICATION = "restricted_phi"
SCOPE_POLICY = "AI-IAM-004"
CLASSIFICATION_POLICY = "AI-DATA-004"


@dataclass
class ControlOutcome:
    result: str
    detail: str
    evidence: list[str] = field(default_factory=list)


@dataclass
class ControlResult:
    control_id: str
    title: str
    requirement: str
    result: str
    detail: str
    evidence: list[str]


def _events_of(events: list[dict], event_type: str) -> list[dict]:
    return [e for e in events if e["event_type"] == event_type]


# --------------------------------------------------------------- predicates

def _agent_identity_required(events: list[dict]) -> ControlOutcome:
    validated = _events_of(events, "identity.validation_succeeded")
    rejected = _events_of(events, "identity.validation_failed")
    executions = _events_of(events, "tool.execution_started")
    if not validated and not rejected:
        return ControlOutcome(NOT_TESTED, "no credential was presented in this session")
    if executions and not validated:
        return ControlOutcome(FAIL, "a tool executed with no successful credential validation")
    return ControlOutcome(
        PASS,
        f"{len(validated)} credential validation(s) succeeded, {len(rejected)} rejected; "
        f"no execution occurred without validation",
        [e["event_id"] for e in validated + rejected],
    )


def _session_bound_credential(events: list[dict]) -> ControlOutcome:
    mismatches = [
        e for e in _events_of(events, "identity.validation_failed")
        if e["payload"].get("reason") == "session_mismatch"
    ]
    bound = [
        e for e in _events_of(events, "identity.validation_succeeded")
        if e["payload"].get("session_bound") is True
    ]
    if mismatches:
        return ControlOutcome(
            PASS,
            "a credential minted for another session was rejected",
            [e["event_id"] for e in mismatches],
        )
    if bound:
        return ControlOutcome(
            PASS,
            f"{len(bound)} credential(s) validated with session binding enforced",
            [e["event_id"] for e in bound],
        )
    return ControlOutcome(NOT_TESTED, "no credential validation occurred")


def _least_privilege_enforced(events: list[dict]) -> ControlOutcome:
    decisions = _events_of(events, "policy.decision")
    if not decisions:
        return ControlOutcome(NOT_TESTED, "no authorization decision was made")
    violations = []
    for d in decisions:
        if d["payload"]["decision"] != "ALLOW":
            continue
        tool = d["payload"]["tool"]
        scope = d["payload"].get("evaluation_input", {}).get("credential_scope", [])
        if tool not in scope:
            violations.append(d["event_id"])
    if violations:
        return ControlOutcome(
            FAIL, "an action was authorized while outside the credential capability scope", violations
        )
    return ControlOutcome(
        PASS,
        f"{len(decisions)} decision(s) evaluated; no action executed outside credential scope",
        [d["event_id"] for d in decisions],
    )


def _restricted_export_prevented(events: list[dict]) -> ControlOutcome:
    # Deliberately specific: this control is satisfied only by a denial of the
    # export action against a PHI-classified resource. An unrelated denial
    # elsewhere in the session must not satisfy it.
    relevant = [
        e for e in _events_of(events, "policy.decision")
        if e["payload"]["tool"] == EXPORT_TOOL
        and e["payload"].get("resource_classification") == PHI_CLASSIFICATION
    ]
    if not relevant:
        return ControlOutcome(
            NOT_TESTED, f"no request for '{EXPORT_TOOL}' against {PHI_CLASSIFICATION} data occurred"
        )
    allowed = [e for e in relevant if e["payload"]["decision"] == "ALLOW"]
    if allowed:
        return ControlOutcome(
            FAIL,
            f"'{EXPORT_TOOL}' against {PHI_CLASSIFICATION} data was authorized",
            [e["event_id"] for e in allowed],
        )
    executed = [
        e for e in _events_of(events, "tool.execution_completed")
        if e["payload"]["tool"] == EXPORT_TOOL
    ]
    if executed:
        return ControlOutcome(
            FAIL, f"'{EXPORT_TOOL}' executed despite denial", [e["event_id"] for e in executed]
        )
    return ControlOutcome(
        PASS,
        f"{len(relevant)} request(s) for '{EXPORT_TOOL}' against {PHI_CLASSIFICATION} data denied "
        f"and not executed",
        [e["event_id"] for e in relevant],
    )


def _classification_backstop(events: list[dict]) -> ControlOutcome:
    """Did the classification rule actually contain an action nothing else would?

    Passing requires evidence of the full condition, not merely that the rule
    fired. If the capability scope or the role grant would have denied the
    request anyway, the classification rule was redundant here and this control
    cannot claim it was load-bearing.

    Required, all from one recorded decision:
      1. the action was inside the credential capability scope    (control PASS)
      2. an explicit role grant permitted the action              (control PASS)
      3. the resource was restricted or PHI-classified
      4. the classification rule denied
      5. the action did not execute
    """
    executed = {
        e["payload"]["tool"] for e in _events_of(events, "tool.execution_completed")
    }
    saw_partial = False

    for e in _events_of(events, "policy.decision"):
        p = e["payload"]
        controls = {c["control"]: c for c in p.get("control_results", [])}
        scope = controls.get("capability_scope")
        grant = controls.get("role_grant")
        classification = controls.get("data_classification")

        if not (scope and grant and classification):
            continue
        if classification["result"] != "DENY":
            continue
        if not str(p.get("resource_classification", "")).startswith("restricted"):
            continue

        if scope["result"] == "PASS" and grant["result"] == "PASS":
            if p["tool"] in executed:
                return ControlOutcome(
                    FAIL,
                    f"'{p['tool']}' executed despite the classification rule denying it",
                    [e["event_id"]],
                )
            return ControlOutcome(
                PASS,
                f"{classification['policy_id']} denied '{p['tool']}' while the capability "
                f"scope and the role grant both permitted it; the classification rule was "
                f"the only control containing the action",
                [e["event_id"]],
            )
        saw_partial = True

    if saw_partial:
        return ControlOutcome(
            NOT_TESTED,
            "the classification rule denied, but another control would have denied the "
            "request anyway, so this evidence does not show it was load-bearing",
        )
    return ControlOutcome(
        NOT_TESTED,
        "no request reached the classification rule with both the capability scope and "
        "the role grant already permitting it",
    )


def _injection_detection(events: list[dict]) -> ControlOutcome:
    retrieved = {e["payload"]["doc_id"] for e in _events_of(events, "rag.document_retrieved")}
    if not retrieved:
        return ControlOutcome(NOT_TESTED, "no untrusted content was retrieved in this session")
    indicators = _events_of(events, "detection.injection_indicator")
    if not indicators:
        return ControlOutcome(
            NOT_TESTED, "untrusted content was retrieved but contained no known indicators"
        )
    orphaned = [e for e in indicators if e["payload"]["doc_id"] not in retrieved]
    if orphaned:
        return ControlOutcome(
            FAIL,
            "an indicator references a document that was never retrieved",
            [e["event_id"] for e in orphaned],
        )
    docs = sorted({e["payload"]["doc_id"] for e in indicators})
    return ControlOutcome(
        PASS,
        f"{len(indicators)} indicator(s) recorded against retrieved source(s): {', '.join(docs)}",
        [e["event_id"] for e in indicators],
    )


def _incident_generated(events: list[dict]) -> ControlOutcome:
    denials = _events_of(events, "tool.execution_denied")
    rejections = _events_of(events, "identity.validation_failed")
    incidents = _events_of(events, "security.incident_created")
    if not denials and not rejections:
        return ControlOutcome(NOT_TESTED, "no denial or credential rejection occurred")
    if len(incidents) < len(denials) + len(rejections):
        return ControlOutcome(
            FAIL,
            f"{len(denials) + len(rejections)} enforcement event(s) but only "
            f"{len(incidents)} incident(s) recorded",
            [e["event_id"] for e in incidents],
        )
    return ControlOutcome(
        PASS,
        f"{len(incidents)} incident(s) created for {len(denials) + len(rejections)} "
        f"enforcement event(s)",
        [e["event_id"] for e in incidents],
    )


def _sensitive_output_screened(events: list[dict]) -> ControlOutcome:
    completions = _events_of(events, "tool.execution_completed")
    if not completions:
        return ControlOutcome(NOT_TESTED, "no tool output was produced in this session")
    dlp = _events_of(events, "dlp.detection")
    if not dlp:
        return ControlOutcome(
            NOT_TESTED, "tool output was produced but contained no sensitive identifiers"
        )
    unredacted = [
        e for e in completions
        if e["payload"]["tool"] in {d["payload"]["tool"] for d in dlp}
        and not e["payload"].get("output_redacted")
    ]
    if unredacted:
        return ControlOutcome(
            FAIL,
            "sensitive identifiers were detected but the output was not redacted",
            [e["event_id"] for e in unredacted],
        )
    return ControlOutcome(
        PASS,
        f"{sum(d['payload']['finding_count'] for d in dlp)} sensitive identifier(s) detected "
        f"and redacted before reaching the agent",
        [e["event_id"] for e in dlp],
    )


def _activity_reconstructable(events: list[dict]) -> ControlOutcome:
    required = ["user.authenticated", "agent.session_created"]
    missing = [t for t in required if not _events_of(events, t)]
    if not events:
        return ControlOutcome(NOT_TESTED, "no events recorded for this session")
    if missing:
        return ControlOutcome(FAIL, f"session origin not reconstructable, missing: {', '.join(missing)}")
    denials = _events_of(events, "tool.execution_denied")
    incidents = _events_of(events, "security.incident_created")
    if denials and not incidents:
        return ControlOutcome(FAIL, "a denial has no corresponding incident to reconstruct from")
    return ControlOutcome(
        PASS,
        f"{len(events)} correlated event(s) span user, agent identity, action and outcome",
        [events[0]["event_id"], events[-1]["event_id"]],
    )


CONTROLS: list[tuple[str, str, str, Callable[[list[dict]], ControlOutcome]]] = [
    ("AC-01", "Agent identity required",
     "Agents must present a validated workload identity before any action.",
     _agent_identity_required),
    ("AC-02", "Session-bound credential",
     "A credential is usable only in the session it was minted for.",
     _session_bound_credential),
    ("AC-03", "Least privilege enforced",
     "No action executes outside the credential's capability scope.",
     _least_privilege_enforced),
    ("AC-04", "Restricted data export prevented",
     "Export of PHI-classified data by a research agent is denied and not executed.",
     _restricted_export_prevented),
    ("AC-05", "Classification backstop is load-bearing",
     "A classification rule contains an action that scope and role grant both permit.",
     _classification_backstop),
    ("AC-06", "Injection detection recorded",
     "Indicators in untrusted content are recorded against their source document.",
     _injection_detection),
    ("AC-07", "Incident generated",
     "Every enforcement action produces a linked security incident.",
     _incident_generated),
    ("AC-08", "Sensitive output screened",
     "Sensitive identifiers in tool output are detected and redacted.",
     _sensitive_output_screened),
    ("AC-09", "Activity reconstructable",
     "Session activity is reconstructable from correlated evidence.",
     _activity_reconstructable),
]

INTEGRITY_CONTROL = (
    "AC-10",
    "Evidence integrity",
    "Evidence verifies against a separately supplied trust anchor.",
)


def assess(
    ledger: EvidenceLedger,
    session_id: str | list[str],
    trust_public_key: bytes,
    expected_head: str | None = None,
) -> list[ControlResult]:
    """Validate controls against recorded evidence for one or more sessions.

    ``trust_public_key`` is required: the integrity control is meaningless if
    the verifier sources its key from beside the evidence it is checking.
    """
    session_ids = [session_id] if isinstance(session_id, str) else list(session_id)
    wanted = set(session_ids)
    events = [e for e in ledger.entries() if e["session_id"] in wanted]
    integrity = verify_ledger(ledger.path, trust_public_key, expected_head=expected_head)

    results: list[ControlResult] = []
    for control_id, title, requirement, predicate in CONTROLS:
        if not integrity["valid"]:
            # Evidence that does not verify cannot support any assertion.
            results.append(
                ControlResult(
                    control_id, title, requirement, FAIL,
                    f"evidence integrity check failed ({integrity['failure']}); "
                    f"no control assertion can rest on this record",
                    [],
                )
            )
            continue
        outcome = predicate(events)
        results.append(
            ControlResult(control_id, title, requirement, outcome.result, outcome.detail, outcome.evidence)
        )

    cid, ctitle, creq = INTEGRITY_CONTROL
    results.append(
        ControlResult(
            cid, ctitle, creq,
            PASS if integrity["valid"] else FAIL,
            integrity["detail"] + f" ({integrity['checked']} events checked)",
            [],
        )
    )
    return results
