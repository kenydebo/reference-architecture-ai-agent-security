"""Evidence-based control validation.

The property that matters most here is negative: a control must not pass on
evidence that is not specific to it.
"""

from __future__ import annotations

import json

from assurance.controls import FAIL, NOT_TESTED, PASS, assess


def _misconfigured_broker(harness):
    """Point the harness broker at a scenario-local misconfigured policy."""
    from copy import deepcopy

    from gateway.authorization import ROLE_GRANTS, AuthorizationEngine

    grants = deepcopy(ROLE_GRANTS)
    research = next(g for g in grants if g["role"] == "research_reader")
    research["allow_tools"] = research["allow_tools"] + ["clinical_data.export"]
    harness.broker.authorizer = AuthorizationEngine(role_grants=grants)
    return harness


def _result(results, control_id):
    return next(r for r in results if r.control_id == control_id)


def _assess(harness, session):
    return assess(harness.ledger, session.session_id, harness.trust_key)


# ------------------------------------------------ the central negative test

def test_unrelated_deny_does_not_satisfy_the_restricted_export_control(harness):
    """A denial of a misspelled tool says nothing about PHI export.

    This is the specific failure this control was rewritten to prevent.
    """
    session = harness.session()
    result = session.request_tool("clinicl.serch", purpose="typo")
    session.close()

    assert result.status == "denied"
    ac04 = _result(_assess(harness, session), "AC-04")
    assert ac04.result == NOT_TESTED
    assert ac04.result != PASS


def test_restricted_export_control_passes_only_on_its_own_evidence(harness):
    session = harness.session()
    session.retrieve("trial results")
    session.request_tool("clinical_data.export", purpose="cross-reference")
    session.close()

    ac04 = _result(_assess(harness, session), "AC-04")
    assert ac04.result == PASS
    assert "clinical_data.export" in ac04.detail


def test_restricted_export_control_fails_if_the_export_were_authorized(harness, monkeypatch):
    """Negative case: if policy ever allowed the export, the control must FAIL."""
    session = harness.session()
    session.request_tool("clinical_data.export", purpose="x")
    session.close()

    # Rewrite the recorded decision to ALLOW and re-sign, so integrity holds
    # and only the control predicate is under test.
    rows = [json.loads(l) for l in harness.path.read_text(encoding="utf-8").splitlines() if l.strip()]
    for row in rows:
        if row["event_type"] == "policy.decision" and row["payload"]["tool"] == "clinical_data.export":
            row["payload"]["decision"] = "ALLOW"
    import hashlib
    from forensics.evidence import _canonical
    prev = "0" * 64
    for row in rows:
        row["prev_hash"] = prev
        view = {k: v for k, v in row.items() if k not in ("event_hash", "signature")}
        row["event_hash"] = hashlib.sha256(_canonical(view)).hexdigest()
        row["signature"] = harness.signer.sign(row["event_hash"].encode("utf-8"))
        prev = row["event_hash"]
    harness.path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")

    ac04 = _result(_assess(harness, session), "AC-04")
    assert ac04.result == FAIL


# ------------------------------------------------------- not-tested states

def test_unexercised_controls_report_not_tested_rather_than_pass(harness):
    """A session that only does authorized work exercises only some controls."""
    session = harness.session()
    session.request_tool("clinical.search", purpose="research")
    session.close()

    results = _assess(harness, session)
    assert _result(results, "AC-04").result == NOT_TESTED   # no export attempted
    assert _result(results, "AC-05").result == NOT_TESTED   # backstop not reached
    assert _result(results, "AC-06").result == NOT_TESTED   # no content retrieved
    assert _result(results, "AC-07").result == NOT_TESTED   # nothing denied
    assert _result(results, "AC-01").result == PASS
    assert _result(results, "AC-03").result == PASS


def test_empty_session_does_not_pass_controls(harness):
    harness.session().close()
    results = assess(harness.ledger, "sess-nonexistent", harness.trust_key)
    assert all(r.result != PASS for r in results if r.control_id != "AC-10")


# --------------------------------------------------------- positive states

def test_classification_backstop_control_requires_every_other_control_to_permit(harness):
    """AC-05 must not pass while any other control would still have denied.

    Overbroad scope alone is not enough: the role grant would have contained
    the request anyway, so the classification rule was not load-bearing.
    """
    normal = harness.session()
    normal.request_tool("clinical_data.export", purpose="x")
    normal.close()
    assert _result(_assess(harness, normal), "AC-05").result == NOT_TESTED

    scope_only = harness.session(
        scope_override=["clinical.search", "documents.summarize", "clinical_data.export"]
    )
    scope_only.request_tool("clinical_data.export", purpose="x")
    scope_only.close()
    assert _result(_assess(harness, scope_only), "AC-05").result == NOT_TESTED


def test_injection_detection_control_links_to_a_retrieved_document(harness):
    session = harness.session()
    session.retrieve("trial results")
    session.close()
    ac06 = _result(_assess(harness, session), "AC-06")
    assert ac06.result == PASS
    assert "vendor-appendix.txt" in ac06.detail


def test_incident_control_requires_one_incident_per_enforcement_event(harness):
    session = harness.session()
    session.request_tool("clinical_data.export", purpose="x")
    session.request_tool("manufacturing.batch_records", purpose="y")
    session.close()
    ac07 = _result(_assess(harness, session), "AC-07")
    assert ac07.result == PASS
    assert len(ac07.evidence) == 2


def test_output_screening_control_is_exercised(harness):
    """DLP must have a live path, not be an architecture diagram label."""
    session = harness.session()
    result = session.request_tool("documents.summarize", purpose="research")
    session.close()
    assert result.redacted is True
    assert "MRN-4471902" not in result.output
    ac08 = _result(_assess(harness, session), "AC-08")
    assert ac08.result == PASS


def test_dlp_evidence_does_not_record_the_detected_value(harness):
    """The evidence record must not copy the identifier it just contained."""
    session = harness.session()
    session.request_tool("documents.summarize", purpose="research")
    session.close()
    raw = harness.path.read_text(encoding="utf-8")
    assert "MRN-4471902" not in raw


def test_session_binding_control_passes_on_a_rejected_replay(harness):
    victim = harness.session()
    harness.broker.invoke(
        session_id="sess-attacker",
        credential=victim.credential,
        tool="clinical.search",
        purpose="replay",
    )
    results = assess(harness.ledger, "sess-attacker", harness.trust_key)
    ac02 = _result(results, "AC-02")
    assert ac02.result == PASS
    assert "another session" in ac02.detail


# ------------------------------------------------------- integrity gating

def test_no_control_passes_when_the_evidence_does_not_verify(harness):
    session = harness.session()
    session.retrieve("trial results")
    session.request_tool("clinical_data.export", purpose="x")
    session.close()
    assert all(r.result == PASS for r in _assess(harness, session) if r.control_id in
               {"AC-01", "AC-04", "AC-10"})

    rows = harness.path.read_text(encoding="utf-8").splitlines()
    idx = next(i for i, r in enumerate(rows) if '"decision": "DENY"' in r)
    rows[idx] = rows[idx].replace('"decision": "DENY"', '"decision": "ALLOW"')
    harness.path.write_text("\n".join(rows) + "\n", encoding="utf-8")

    results = _assess(harness, session)
    assert all(r.result == FAIL for r in results)
    assert "integrity" in _result(results, "AC-04").detail


def test_integrity_control_fails_on_an_empty_ledger(harness):
    session = harness.session()
    session.close()
    harness.path.write_text("", encoding="utf-8")
    results = _assess(harness, session)
    assert _result(results, "AC-10").result == FAIL


def test_assess_accepts_multiple_sessions(harness):
    a = harness.session()
    a.retrieve("trial results")
    a.request_tool("clinical_data.export", purpose="x")
    a.close()
    _misconfigured_broker(harness)
    b = harness.session(
        scope_override=["clinical.search", "documents.summarize", "clinical_data.export"]
    )
    b.request_tool("clinical_data.export", purpose="y")
    b.close()

    combined = assess(harness.ledger, [a.session_id, b.session_id], harness.trust_key)
    assert _result(combined, "AC-04").result == PASS
    assert _result(combined, "AC-05").result == PASS
    assert _result(combined, "AC-06").result == PASS


# ------------------------------------------- AC-05 load-bearing evidence

def test_ac05_not_tested_when_default_deny_would_still_contain_the_request(harness):
    """Overbroad scope alone does not prove the classification rule mattered.

    The role grant would have denied this request regardless, so AC-05 must not
    claim the classification rule was load-bearing.
    """
    session = harness.session(scope_override=["clinical_data.export"])
    session.request_tool("clinical_data.export", purpose="x")
    session.close()

    ac05 = _result(_assess(harness, session), "AC-05")
    assert ac05.result == NOT_TESTED
    assert "would have denied" in ac05.detail


def test_ac05_not_tested_when_scope_also_denies(harness):
    session = harness.session()
    session.request_tool("clinical_data.export", purpose="x")
    session.close()
    assert _result(_assess(harness, session), "AC-05").result == NOT_TESTED


def test_ac05_passes_only_under_dual_misconfiguration(harness):
    """Scope permits, role grant permits, classification denies, nothing ran."""
    _misconfigured_broker(harness)
    session = harness.session(
        scope_override=["clinical.search", "documents.summarize", "clinical_data.export"]
    )
    result = session.request_tool("clinical_data.export", purpose="x")
    session.close()

    assert result.status == "denied"
    assert result.decision.control_passed("capability_scope") is True
    assert result.decision.control_passed("role_grant") is True

    ac05 = _result(_assess(harness, session), "AC-05")
    assert ac05.result == PASS
    assert "AI-DATA-004" in ac05.detail


def test_evidence_records_control_passes_not_only_denials(harness):
    """AC-05 is only checkable because passing verdicts are recorded."""
    session = harness.session()
    session.request_tool("clinical.search", purpose="x")
    session.close()
    decision = next(
        e for e in harness.ledger.session(session.session_id)
        if e["event_type"] == "policy.decision"
    )
    controls = {c["control"]: c["result"] for c in decision["payload"]["control_results"]}
    assert controls == {
        "capability_scope": "PASS",
        "data_classification": "PASS",
        "role_grant": "PASS",
    }
