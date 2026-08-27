"""
Forensic reconstruction of an AI-agent session from recorded evidence.

Everything here is derived from the events in the ledger. No agent name, user
id, SPIFFE id, tool name, policy id or incident id is hardcoded: a
reconstruction that asserts conclusions it did not read from evidence is not a
reconstruction. Where a session contains several denials or several incidents,
all of them are reported rather than silently showing the first.

Output is ASCII-only so it renders on any console encoding.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from forensics.evidence import EvidenceLedger


@dataclass
class ToolAttempt:
    tool: str
    purpose: str
    decision: str
    policy_id: str
    reason: str
    resource_system: str
    resource_classification: str
    matched_deny_policies: list[str] = field(default_factory=list)
    executed: bool = False
    output_redacted: bool = False


@dataclass
class Reconstruction:
    session_id: str
    user: str | None
    agent_id: str | None
    spiffe_id: str | None
    role: str | None
    credential_scope: list[str]
    documents: list[str]
    suspicious_documents: list[dict]
    attempts: list[ToolAttempt]
    incidents: list[dict]
    identity_failures: list[dict]
    dlp_events: list[dict]
    event_count: int

    @property
    def denied_attempts(self) -> list[ToolAttempt]:
        return [a for a in self.attempts if a.decision == "DENY"]


def _first_payload(events: list[dict], event_type: str, key: str, default=None):
    for e in events:
        if e["event_type"] == event_type:
            return e["payload"].get(key, default)
    return default


def reconstruct(ledger: EvidenceLedger, session_id: str) -> Reconstruction:
    events = ledger.session(session_id)

    user = next(
        (e["actor"].get("user") for e in events if e["event_type"] == "user.authenticated"),
        None,
    )
    agent_id = next(
        (e["actor"].get("agent") for e in events if e["event_type"] == "agent.session_created"),
        None,
    )

    documents = [
        e["payload"]["doc_id"] for e in events if e["event_type"] == "rag.document_retrieved"
    ]
    suspicious = [
        {
            "doc_id": e["payload"]["doc_id"],
            "category": e["payload"]["category"],
            "matched_text": e["payload"].get("matched_text", ""),
            "event_id": e["event_id"],
        }
        for e in events
        if e["event_type"] == "detection.injection_indicator"
    ]

    # Pair each request with the decision that followed it, in order.
    requests = [e for e in events if e["event_type"] == "agent.tool_requested"]
    decisions = [e for e in events if e["event_type"] == "policy.decision"]
    completions = {
        e["payload"]["tool"]: e for e in events if e["event_type"] == "tool.execution_completed"
    }

    # Pair by the broker's request id where it is present. Position and tool
    # name are only sound while one session issues one request at a time.
    decisions_by_request = {
        d["payload"]["request_id"]: d for d in decisions if "request_id" in d["payload"]
    }
    completions_by_request = {
        e["payload"]["request_id"]: e
        for e in events
        if e["event_type"] == "tool.execution_completed" and "request_id" in e["payload"]
    }

    attempts: list[ToolAttempt] = []
    for i, req in enumerate(requests):
        request_id = req["payload"].get("request_id")
        dec = decisions_by_request.get(request_id) if request_id else None
        if dec is None:
            dec = decisions[i] if i < len(decisions) else None
        if dec is None:
            continue
        p = dec["payload"]
        completion = (
            completions_by_request.get(request_id)
            if request_id
            else completions.get(p["tool"])
        )
        attempts.append(
            ToolAttempt(
                tool=p["tool"],
                purpose=req["payload"].get("purpose", ""),
                decision=p["decision"],
                policy_id=p["policy_id"],
                reason=p["reason"],
                resource_system=p.get("resource_system", "unknown"),
                resource_classification=p.get("resource_classification", "unknown"),
                matched_deny_policies=[
                    d["policy_id"] for d in p.get("matched_deny_policies", [])
                ],
                executed=completion is not None,
                output_redacted=bool(completion and completion["payload"].get("output_redacted")),
            )
        )

    incidents = [
        {**e["payload"], "event_id": e["event_id"], "timestamp": e["timestamp"]}
        for e in events
        if e["event_type"] == "security.incident_created"
    ]
    identity_failures = [
        {**e["payload"], "event_id": e["event_id"]}
        for e in events
        if e["event_type"] == "identity.validation_failed"
    ]
    dlp_events = [
        {**e["payload"], "event_id": e["event_id"]}
        for e in events
        if e["event_type"] == "dlp.detection"
    ]

    return Reconstruction(
        session_id=session_id,
        user=user,
        agent_id=agent_id,
        spiffe_id=_first_payload(events, "agent.session_created", "spiffe_id"),
        role=_first_payload(events, "agent.session_created", "role"),
        credential_scope=_first_payload(events, "agent.session_created", "credential_scope", []) or [],
        documents=documents,
        suspicious_documents=suspicious,
        attempts=attempts,
        incidents=incidents,
        identity_failures=identity_failures,
        dlp_events=dlp_events,
        event_count=len(events),
    )


_DESCRIBERS = {
    "user.authenticated": lambda e: f"user authenticated: {e['actor'].get('user')}",
    "agent.session_created": lambda e: (
        f"agent session created: {e['actor'].get('agent')} "
        f"[{e['payload']['spiffe_id']}] scope={e['payload']['credential_scope']}"
    ),
    "identity.validation_succeeded": lambda e: (
        f"credential validated (session-bound) for {e['payload']['agent_id']}"
    ),
    "identity.validation_failed": lambda e: (
        f"** CREDENTIAL REJECTED: {e['payload']['reason']} - {e['payload']['detail']}"
    ),
    "rag.query": lambda e: f"retrieval query: \"{e['payload']['query']}\"",
    "rag.document_retrieved": lambda e: f"document retrieved: {e['payload']['doc_id']}",
    "detection.injection_indicator": lambda e: (
        f"** INJECTION INDICATOR in {e['payload']['doc_id']}: "
        f"{e['payload']['category']} (\"{e['payload']['matched_text']}\")"
    ),
    "agent.tool_requested": lambda e: (
        f"agent requested tool: {e['payload']['tool']} (purpose: {e['payload']['purpose']})"
    ),
    "policy.decision": lambda e: (
        f"policy decision: {e['payload']['decision']} [{e['payload']['policy_id']}] "
        f"on {e['payload']['tool']} ({e['payload']['resource_classification']}) - "
        f"{e['payload']['reason']}"
    ),
    "tool.execution_denied": lambda e: f"execution denied: {e['payload']['tool']}",
    "tool.execution_started": lambda e: f"executing: {e['payload']['tool']}",
    "tool.execution_completed": lambda e: (
        f"execution completed: {e['payload']['tool']}"
        + (" (output redacted)" if e["payload"].get("output_redacted") else "")
    ),
    "dlp.detection": lambda e: (
        f"** DLP: {e['payload']['finding_count']} sensitive identifier(s) in "
        f"{e['payload']['tool']} output -> {e['payload']['action']}"
    ),
    "security.incident_created": lambda e: (
        f"** INCIDENT {e['payload']['incident_id']} [{e['payload']['severity']}]: "
        f"{e['payload']['title']}"
    ),
    "agent.session_closed": lambda e: "agent session closed",
}


def timeline(ledger: EvidenceLedger, session_id: str) -> str:
    """Chronological, event-derived session timeline."""
    lines = []
    for e in ledger.session(session_id):
        clock = e["timestamp"].split("T")[1][:8]
        describe = _DESCRIBERS.get(e["event_type"])
        desc = describe(e) if describe else e["event_type"]
        lines.append(f"{clock}  seq{e['seq']:<3} {desc}")
    return "\n".join(lines)


def causal_chain(r: Reconstruction) -> str:
    """Render the causal path an investigator needs to follow."""
    out = ["USER", f"  -> {r.user}", "AGENT", f"  -> {r.agent_id}  [{r.spiffe_id}]", f"     role={r.role}  scope={r.credential_scope}"]

    out.append("RETRIEVED DOCUMENTS")
    flagged = {d["doc_id"] for d in r.suspicious_documents}
    for doc in r.documents:
        mark = "   <-- SUSPICIOUS INSTRUCTION" if doc in flagged else ""
        out.append(f"  -> {doc}{mark}")

    if r.suspicious_documents:
        out.append("SUSPICIOUS INSTRUCTION")
        for d in r.suspicious_documents:
            out.append(f"  -> {d['doc_id']}: {d['category']} (\"{d['matched_text']}\")")

    if r.identity_failures:
        out.append("CREDENTIAL FAILURES")
        for f in r.identity_failures:
            out.append(f"  -> {f['reason']}: {f['detail']}")

    out.append("TOOL REQUESTS")
    for a in r.attempts:
        out.append(f"  -> {a.tool}  ({a.resource_system} / {a.resource_classification})")
        policies = ", ".join(a.matched_deny_policies) if a.matched_deny_policies else a.policy_id
        out.append(f"     POLICY   {policies}")
        out.append(f"     DECISION {a.decision}  executed={a.executed}")
        out.append(f"     REASON   {a.reason}")

    if r.dlp_events:
        out.append("OUTPUT SCREENING")
        for d in r.dlp_events:
            out.append(f"  -> {d['tool']}: {d['finding_count']} finding(s), action={d['action']}")

    out.append("SECURITY INCIDENTS")
    if r.incidents:
        for i in r.incidents:
            out.append(f"  -> {i['incident_id']} [{i['severity']}] {i['title']}")
    else:
        out.append("  -> none")

    return "\n".join(out)


def investigation_answers(r: Reconstruction) -> list[tuple[str, str]]:
    """The questions an investigator asks, answered from evidence only."""
    denied = r.denied_attempts
    first_denied = denied[0] if denied else None
    suspicious = r.suspicious_documents[0] if r.suspicious_documents else None
    return [
        ("Who initiated the session?", r.user or "unknown"),
        ("Which agent executed?", r.agent_id or "unknown"),
        ("Which identity was used?", r.spiffe_id or "unknown"),
        ("Which documents were retrieved?", ", ".join(r.documents) or "none"),
        (
            "Which document contained a suspicious instruction?",
            f"{suspicious['doc_id']} ({suspicious['category']})" if suspicious else "none detected",
        ),
        (
            "What tool did the agent attempt to invoke?",
            ", ".join(a.tool for a in r.attempts) or "none",
        ),
        (
            "What resource was targeted?",
            ", ".join(
                f"{a.resource_system} [{a.resource_classification}]" for a in r.attempts
            )
            or "none",
        ),
        (
            "Which policy evaluated the request?",
            ", ".join(sorted({p for a in r.attempts for p in (a.matched_deny_policies or [a.policy_id])}))
            or "none",
        ),
        ("What decision was made?", ", ".join(f"{a.tool}={a.decision}" for a in r.attempts) or "none"),
        ("Why?", first_denied.reason if first_denied else "no denial in this session"),
        (
            "Was the request executed?",
            ", ".join(f"{a.tool}={'yes' if a.executed else 'no'}" for a in r.attempts) or "none",
        ),
        (
            "Which security incident was created?",
            ", ".join(f"{i['incident_id']} [{i['severity']}]" for i in r.incidents) or "none",
        ),
    ]
