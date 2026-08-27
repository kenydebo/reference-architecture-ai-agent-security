"""Evidence integrity and forensic reconstruction."""

from __future__ import annotations

import hashlib
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from forensics.evidence import (
    EvidenceLedger,
    LedgerSigner,
    _canonical,
    verify_ledger,
)
from forensics.reconstruct import causal_chain, investigation_answers, reconstruct, timeline


def _populate(harness):
    session = harness.session()
    session.retrieve("trial results")
    session.request_tool("clinical.search", purpose="research")
    session.request_tool("clinical_data.export", purpose="cross-reference")
    session.close()
    return session


def _rows(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _write(path, rows):
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")


def _rechain(rows, signer, start_prev="0" * 64):
    """Rebuild hashes and signatures so only the signature check can object."""
    prev = start_prev
    for row in rows:
        row["prev_hash"] = prev
        view = {k: v for k, v in row.items() if k not in ("event_hash", "signature")}
        row["event_hash"] = hashlib.sha256(_canonical(view)).hexdigest()
        row["signature"] = signer.sign(row["event_hash"].encode("utf-8"))
        prev = row["event_hash"]
    return rows


# ------------------------------------------------------------ happy path

def test_clean_ledger_verifies(harness):
    _populate(harness)
    report = verify_ledger(harness.path, harness.trust_key)
    assert report["valid"] is True
    assert report["checked"] > 0
    assert report["failure"] is None


def test_verification_accepts_a_pem_or_a_key_object(harness):
    from forensics.evidence import load_trust_key

    _populate(harness)
    assert verify_ledger(harness.path, harness.trust_key)["valid"]
    assert verify_ledger(harness.path, load_trust_key(harness.trust_key))["valid"]


# ---------------------------------------------------------- tamper modes

def test_modified_record_is_detected(harness):
    _populate(harness)
    rows = _rows(harness.path)
    target = next(
        i for i, r in enumerate(rows)
        if r["event_type"] == "policy.decision" and r["payload"]["decision"] == "DENY"
    )
    rows[target]["payload"]["decision"] = "ALLOW"
    _write(harness.path, rows)

    report = verify_ledger(harness.path, harness.trust_key)
    assert report["valid"] is False
    assert report["failure"] == "CONTENT_TAMPERED"
    assert report["at_seq"] == rows[target]["seq"]


def test_broken_chain_is_detected(harness):
    _populate(harness)
    rows = _rows(harness.path)
    del rows[3]
    _write(harness.path, rows)

    report = verify_ledger(harness.path, harness.trust_key)
    assert report["valid"] is False
    assert report["failure"] == "CHAIN_BREAK"


def test_reordered_entries_are_detected(harness):
    _populate(harness)
    rows = _rows(harness.path)
    rows[2], rows[3] = rows[3], rows[2]
    _write(harness.path, rows)
    assert verify_ledger(harness.path, harness.trust_key)["failure"] == "CHAIN_BREAK"


def test_rehashed_record_fails_signature_check(harness):
    """Recomputing the hash without the key defeats the chain, not the seal."""
    _populate(harness)
    rows = _rows(harness.path)
    target = next(
        i for i, r in enumerate(rows)
        if r["event_type"] == "policy.decision" and r["payload"]["decision"] == "DENY"
    )
    rows[target]["payload"]["decision"] = "ALLOW"
    view = {k: v for k, v in rows[target].items() if k not in ("event_hash", "signature")}
    rows[target]["event_hash"] = hashlib.sha256(_canonical(view)).hexdigest()
    prev = rows[target]["event_hash"]
    for row in rows[target + 1:]:
        row["prev_hash"] = prev
        v = {k: val for k, val in row.items() if k not in ("event_hash", "signature")}
        row["event_hash"] = hashlib.sha256(_canonical(v)).hexdigest()
        prev = row["event_hash"]
    _write(harness.path, rows)

    report = verify_ledger(harness.path, harness.trust_key)
    assert report["valid"] is False
    assert report["failure"] == "BAD_SIGNATURE"


def test_wholesale_rewrite_with_a_replacement_key_is_detected(harness):
    """The trust-anchor property.

    An attacker who controls the evidence directory rewrites the history and
    re-signs every entry with a key they generated. Verification against the
    independently held trust anchor must reject it. Verification that sourced
    its key from beside the evidence would report this history as valid.
    """
    _populate(harness)
    rows = _rows(harness.path)
    rows = [r for r in rows if r["event_type"] != "security.incident_created"]
    for row in rows:
        if row["event_type"] == "policy.decision":
            row["payload"]["decision"] = "ALLOW"
    for i, row in enumerate(rows):
        row["seq"] = i

    attacker = LedgerSigner(Ed25519PrivateKey.generate())
    _write(harness.path, _rechain(rows, attacker))

    # Self-consistent under the attacker's own key ...
    assert verify_ledger(harness.path, attacker.public_key_pem())["valid"] is True
    # ... and rejected under the real trust anchor.
    report = verify_ledger(harness.path, harness.trust_key)
    assert report["valid"] is False
    assert report["failure"] == "BAD_SIGNATURE"


# --------------------------------------------------------- empty evidence

def test_empty_ledger_is_not_a_successful_integrity_assessment(harness):
    harness.path.write_text("", encoding="utf-8")
    report = verify_ledger(harness.path, harness.trust_key)
    assert report["valid"] is False
    assert report["failure"] == "NO_EVIDENCE"


def test_missing_ledger_is_not_a_successful_integrity_assessment(harness, tmp_path):
    report = verify_ledger(tmp_path / "absent.log", harness.trust_key)
    assert report["valid"] is False
    assert report["failure"] == "NO_EVIDENCE"


def test_malformed_line_is_reported(harness):
    _populate(harness)
    with open(harness.path, "a", encoding="utf-8") as f:
        f.write("{not json\n")
    assert verify_ledger(harness.path, harness.trust_key)["failure"] == "MALFORMED_ENTRY"


# ------------------------------------------------------------- truncation

def test_truncation_is_detected_when_the_head_is_retained(harness):
    _populate(harness)
    head = harness.ledger.head
    rows = _rows(harness.path)
    _write(harness.path, rows[:-3])

    report = verify_ledger(harness.path, harness.trust_key, expected_head=head)
    assert report["valid"] is False
    assert report["failure"] == "TRUNCATED"


def test_truncation_is_undetectable_without_a_retained_head(harness):
    """Documents a known limitation rather than hiding it.

    A backward-linking chain does not commit to the existence of the next
    entry, so tail truncation is indistinguishable from a session that ended
    earlier. Detecting it requires an independently retained head.
    """
    _populate(harness)
    rows = _rows(harness.path)
    _write(harness.path, rows[:-3])
    assert verify_ledger(harness.path, harness.trust_key)["valid"] is True


def test_head_matches_the_last_entry_hash(harness):
    _populate(harness)
    assert harness.ledger.head == _rows(harness.path)[-1]["event_hash"]


# --------------------------------------------------------- reconstruction

def test_reconstruction_derives_facts_from_events(harness):
    session = _populate(harness)
    r = reconstruct(harness.ledger, session.session_id)
    assert r.user == "researcher-023"
    assert r.agent_id == "agent:research-reader"
    assert r.spiffe_id == "spiffe://ai-agents.internal/research-reader"
    assert r.role == "research_reader"
    assert "vendor-appendix.txt" in r.documents
    assert {d["doc_id"] for d in r.suspicious_documents} == {"vendor-appendix.txt"}
    assert len(r.attempts) == 2
    assert len(r.denied_attempts) == 1
    assert r.denied_attempts[0].tool == "clinical_data.export"
    assert r.incidents


def test_reconstruction_is_not_hardcoded_to_one_agent(harness):
    """Change the acting workload; the reconstruction must follow the evidence."""
    session = harness.session(agent_id="agent:ops-analyst")
    session.request_tool("erp.query", purpose="ops")
    session.close()
    r = reconstruct(harness.ledger, session.session_id)
    assert r.agent_id == "agent:ops-analyst"
    assert r.spiffe_id == "spiffe://ai-agents.internal/ops-analyst"
    assert r.role == "ops_reader"


def test_reconstruction_reports_every_denial_and_incident(harness):
    session = harness.session()
    session.request_tool("clinical_data.export", purpose="one")
    session.request_tool("manufacturing.batch_records", purpose="two")
    session.request_tool("clinicl.serch", purpose="three")
    session.close()
    r = reconstruct(harness.ledger, session.session_id)
    assert len(r.denied_attempts) == 3
    assert len(r.incidents) == 3
    assert len({i["incident_id"] for i in r.incidents}) == 3
    rendered = causal_chain(r)
    for attempt in r.denied_attempts:
        assert attempt.tool in rendered


def test_investigation_answers_come_from_evidence(harness):
    session = _populate(harness)
    r = reconstruct(harness.ledger, session.session_id)
    answers = dict(investigation_answers(r))
    assert answers["Who initiated the session?"] == "researcher-023"
    assert "vendor-appendix.txt" in answers["Which document contained a suspicious instruction?"]
    assert "clinical_data.export" in answers["What tool did the agent attempt to invoke?"]
    assert "restricted_phi" in answers["What resource was targeted?"]
    assert "clinical_data.export=no" in answers["Was the request executed?"]


def test_timeline_is_ascii_only(harness):
    session = _populate(harness)
    rendered = timeline(harness.ledger, session.session_id) + causal_chain(
        reconstruct(harness.ledger, session.session_id)
    )
    assert rendered.isascii(), "console output must render on any terminal encoding"


def test_sessions_are_isolated(harness):
    a = harness.session("researcher-023")
    b = harness.session("researcher-099")
    a.request_tool("clinical.search", purpose="x")
    b.request_tool("clinical_data.export", purpose="y")
    a.close()
    b.close()
    assert reconstruct(harness.ledger, a.session_id).denied_attempts == []
    assert len(reconstruct(harness.ledger, b.session_id).denied_attempts) == 1
