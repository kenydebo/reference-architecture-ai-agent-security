"""Workload identity: minting, validation, and every rejection path."""

from __future__ import annotations

import base64
import json

import pytest

from gateway.identity import IdentityError, IdentityProvider


def test_valid_credential_validates_in_its_own_session():
    idp = IdentityProvider()
    minted = idp.mint("agent:research-reader", "sess-1")
    claims = idp.validate(minted["credential"], "sess-1")
    assert claims["agent_id"] == "agent:research-reader"
    assert claims["role"] == "research_reader"
    assert claims["sid"] == "sess-1"


def test_credential_is_scope_limited_to_registered_capabilities():
    idp = IdentityProvider()
    claims = idp.mint("agent:research-reader", "sess-1")["claims"]
    assert claims["scope"] == ["clinical.search", "documents.summarize"]
    assert "clinical_data.export" not in claims["scope"]


def test_credential_is_short_lived():
    idp = IdentityProvider(ttl_seconds=900)
    claims = idp.mint("agent:research-reader", "sess-1")["claims"]
    assert claims["exp"] - claims["iat"] == 900


def test_expired_credential_is_rejected():
    idp = IdentityProvider(ttl_seconds=-1)
    minted = idp.mint("agent:research-reader", "sess-1")
    with pytest.raises(IdentityError) as exc:
        idp.validate(minted["credential"], "sess-1")
    assert exc.value.reason == "expired"


def test_modified_credential_tag_is_rejected():
    idp = IdentityProvider()
    cred = idp.mint("agent:research-reader", "sess-1")["credential"]
    body, tag = cred.rsplit(".", 1)
    flipped = tag[:-1] + ("0" if tag[-1] != "0" else "1")
    with pytest.raises(IdentityError) as exc:
        idp.validate(f"{body}.{flipped}", "sess-1")
    assert exc.value.reason == "bad_signature"


def test_modified_claims_are_rejected():
    """Widening the scope inside the credential invalidates the tag."""
    idp = IdentityProvider()
    minted = idp.mint("agent:research-reader", "sess-1")
    claims = dict(minted["claims"])
    claims["scope"] = claims["scope"] + ["clinical_data.export"]
    forged_body = base64.urlsafe_b64encode(
        json.dumps(claims, sort_keys=True).encode("utf-8")
    ).decode("ascii")
    tag = minted["credential"].rsplit(".", 1)[1]
    with pytest.raises(IdentityError) as exc:
        idp.validate(f"{forged_body}.{tag}", "sess-1")
    assert exc.value.reason == "bad_signature"


def test_credential_from_another_session_is_rejected():
    """Session binding: an intact, unexpired credential is still not portable."""
    idp = IdentityProvider()
    cred = idp.mint("agent:research-reader", "sess-1")["credential"]
    idp.validate(cred, "sess-1")  # valid where it was minted
    with pytest.raises(IdentityError) as exc:
        idp.validate(cred, "sess-2")
    assert exc.value.reason == "session_mismatch"


def test_unknown_workload_cannot_be_minted():
    idp = IdentityProvider()
    with pytest.raises(IdentityError) as exc:
        idp.mint("agent:does-not-exist", "sess-1")
    assert exc.value.reason == "unknown_workload"


@pytest.mark.parametrize("bad", ["", "no-separator", "....", "a.b.c.d"])
def test_malformed_credentials_are_rejected(bad):
    idp = IdentityProvider()
    with pytest.raises(IdentityError):
        idp.validate(bad, "sess-1")


def test_credentials_from_different_providers_do_not_interoperate():
    a, b = IdentityProvider(), IdentityProvider()
    cred = a.mint("agent:research-reader", "sess-1")["credential"]
    with pytest.raises(IdentityError) as exc:
        b.validate(cred, "sess-1")
    assert exc.value.reason == "bad_signature"


def test_rejected_credential_produces_security_evidence(harness):
    """An identity failure must never be a silent exception."""
    victim = harness.session()
    result = harness.broker.invoke(
        session_id="sess-attacker",
        credential=victim.credential,
        tool="clinical.search",
        purpose="replay",
    )
    assert result.status == "identity_rejected"
    events = harness.ledger.session("sess-attacker")
    types = [e["event_type"] for e in events]
    assert "identity.validation_failed" in types
    assert "security.incident_created" in types
    failure = next(e for e in events if e["event_type"] == "identity.validation_failed")
    assert failure["payload"]["reason"] == "session_mismatch"


def test_rejected_credential_does_not_execute_the_tool(harness):
    victim = harness.session()
    harness.broker.invoke(
        session_id="sess-attacker",
        credential=victim.credential,
        tool="clinical.search",
        purpose="replay",
    )
    types = [e["event_type"] for e in harness.ledger.session("sess-attacker")]
    assert "tool.execution_started" not in types
    assert "tool.execution_completed" not in types
