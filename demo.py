"""
AI Agent Security Reference Architecture - end-to-end demonstration.

    python demo.py

Runs the four scenarios against a single shared evidence ledger, then validates
every control against the accumulated evidence and verifies that evidence
against a trust anchor supplied separately from the evidence.

No network access, no API key, and no model call is required.
"""

from __future__ import annotations

from assurance.controls import FAIL, NOT_TESTED, PASS, assess
from forensics.evidence import verify_ledger
from scenarios._common import banner, build_environment, kv, rule, section
from scenarios.investigate_incident import run as run_investigation
from scenarios.normal_request import run as run_normal
from scenarios.overprivileged_token import run as run_overprivileged
from scenarios.prompt_injection import run as run_injection


def demonstrate_credential_misuse(env, victim_session) -> str:
    """Present a valid credential from one session inside another session.

    The credential is cryptographically intact and unexpired. It is rejected
    because it is bound to a different session, and the rejection is recorded
    as evidence rather than raised and discarded.
    """
    banner("CREDENTIAL MISUSE", "A valid credential replayed into another session")
    attacker_session = "sess-replayed01"
    result = env.broker.invoke(
        session_id=attacker_session,
        credential=victim_session.credential,
        tool="clinical.search",
        purpose="replay",
        args={},
    )
    kv("Credential", "valid signature, unexpired")
    kv("Presented in session", attacker_session)
    kv("Minted for session", victim_session.session_id)
    kv("Outcome", result.status)
    kv("Reason", result.reason)
    kv("Incident", result.incident_id)
    print()
    print("A rejected credential is a security event, not a silent exception.")
    return attacker_session


def main() -> None:
    print("=" * 66)
    print("AI AGENT SECURITY REFERENCE ARCHITECTURE")
    print("Keny - personal engineering project")
    print("=" * 66)
    print("Synthetic data, fictional environment, deterministic planner.")
    print("No model call and no API key is required to run this.")

    env = build_environment("demo")

    normal = run_normal(env)
    run_injection(env)
    run_overprivileged(env)
    run_investigation(env)
    demonstrate_credential_misuse(env, normal["session"])

    session_ids = sorted({e["session_id"] for e in env.ledger.entries()})

    banner("SUMMARY", "Controls validated against all evidence from this run")
    results = assess(env.ledger, session_ids, env.trust_public_key)
    integrity = verify_ledger(env.ledger.path, env.trust_public_key)

    print(f"{'Control':<8}{'Result':<12}{'Title'}")
    rule()
    for c in results:
        print(f"{c.control_id:<8}{c.result:<12}{c.title}")

    passed = sum(1 for c in results if c.result == PASS)
    untested = sum(1 for c in results if c.result == NOT_TESTED)
    failed = sum(1 for c in results if c.result == FAIL)

    section("Result")
    kv("Controls passed", passed, 26)
    kv("Controls not exercised", untested, 26)
    kv("Controls failed", failed, 26)
    kv("Evidence integrity", "VERIFIED" if integrity["valid"] else "FAILED", 26)
    kv("Events in ledger", integrity["checked"], 26)
    print()
    print("Each scenario reports NOT_TESTED for controls it does not exercise;")
    print("this summary aggregates the evidence from all of them.")
    print("Run 'pytest' for the positive and negative cases behind each control.")


if __name__ == "__main__":
    main()
