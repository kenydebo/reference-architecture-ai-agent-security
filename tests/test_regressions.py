import pytest
from scenarios._common import build_environment
from scenarios.prompt_injection import run as run_injection
from scenarios.overprivileged_token import run as run_over
from gateway.authorization import AuthorizationEngine
from gateway.identity import IdentityError, IdentityProvider
from forensics.reconstruct import reconstruct


def test_scenario_three_does_not_change_later_authorization():
    env = build_environment("t_order")
    run_over(env, verbose=False)
    after = run_injection(env, verbose=False)
    assert sorted(d.policy_id for d in after["result"].decision.deny_reasons) == [
        "AI-DATA-004", "AI-DEFAULT-DENY", "AI-IAM-004"]


def test_scenario_four_investigates_the_supplied_incident():
    from scenarios.investigate_incident import run as run_inv
    env = build_environment("t_wiring")
    produced = run_injection(env, verbose=False)
    inv = run_inv(env, verbose=False, produced=produced)
    assert inv["session"].session_id == produced["session"].session_id
    assert len({e["session_id"] for e in env.ledger.entries()
                if e["event_type"] == "detection.injection_indicator"}) == 1


def test_reconstruction_does_not_misattribute_execution_by_tool_name():
    env = build_environment("t_recon")
    s = env.new_session("researcher-023")
    s.request_tool("clinical.search", purpose="p1")
    env.broker.authorizer = AuthorizationEngine(role_grants=[])
    s.request_tool("clinical.search", purpose="p2")
    s.close()
    denied = [a for a in reconstruct(env.ledger, s.session_id).attempts if a.decision == "DENY"]
    assert denied and all(a.executed is False for a in denied)


@pytest.mark.parametrize("credential", ["credéntial.deadbeef", "\U0001F600.abc", b"abc.def", None, "", "nodot"])
def test_every_malformed_credential_leaves_by_the_identity_error_path(credential):
    with pytest.raises(IdentityError):
        IdentityProvider().validate(credential, "sess-x")


BROKER_EVENTS = {
    "identity.validation_succeeded", "identity.validation_failed", "agent.tool_requested",
    "policy.decision", "tool.execution_denied", "tool.execution_started",
    "tool.execution_completed", "dlp.detection", "security.incident_created",
}


def test_every_broker_event_carries_the_request_id():
    env = build_environment("t_rid")
    s = env.new_session("researcher-023")
    s.request_tool("documents.summarize", purpose="p")
    s.request_tool("clinical_data.export", purpose="p")
    env.broker.invoke(session_id="other", credential=s.credential, tool="clinical.search", purpose="p")
    s.close()
    missing = [
        e["event_type"] for e in env.ledger.entries()
        if e["event_type"] in BROKER_EVENTS and "request_id" not in e["payload"]
    ]
    assert missing == []


def test_incident_is_joinable_to_the_decision_that_caused_it():
    env = build_environment("t_join")
    s = env.new_session("researcher-023")
    r = s.request_tool("clinical_data.export", purpose="p")
    s.close()
    events = env.ledger.session(s.session_id)
    decision = next(e for e in events if e["event_type"] == "policy.decision")
    incident = next(e for e in events if e["event_type"] == "security.incident_created")
    assert incident["payload"]["request_id"] == decision["payload"]["request_id"]
    assert incident["payload"]["incident_id"] == r.incident_id
