"""
Scenario 4 - Investigation and control validation.

Takes the incident produced by the prompt-injection scenario and reconstructs
it from recorded evidence alone: who initiated the session, which agent and
identity acted, which document carried the instruction, what was requested,
which policy decided, what the decision was, whether it executed, and which
incident was raised.

Then validates security controls against that same evidence, and verifies the
evidence itself against a trust anchor held independently of the ledger.
"""

from __future__ import annotations

from assurance.controls import assess
from forensics.evidence import verify_ledger
from forensics.reconstruct import causal_chain, investigation_answers, reconstruct, timeline
from scenarios._common import Environment, banner, build_environment, kv, rule, section
from scenarios.prompt_injection import run as run_injection


def run(env: Environment | None = None, verbose: bool = True,
        produced: dict | None = None) -> dict:
    env = env or build_environment("investigate_incident")
    # Investigate the incident the injection scenario already produced. Only
    # create one when this scenario is run standalone.
    produced = produced if produced is not None else run_injection(env=env, verbose=False)
    session = produced["session"]

    if verbose:
        banner("SCENARIO 4", "Incident reconstruction and control validation")

    r = reconstruct(env.ledger, session.session_id)

    if verbose:
        section("Timeline (reconstructed from recorded evidence)")
        print(timeline(env.ledger, session.session_id))

        section("Investigation")
        for question, answer in investigation_answers(r):
            print(f"  {question}")
            print(f"    {answer}")

        section("Causal chain")
        print(causal_chain(r))

    # Integrity is checked against a key held by the verifier, not one stored
    # next to the evidence.
    integrity = verify_ledger(env.ledger.path, env.trust_public_key)
    results = assess(env.ledger, session.session_id, env.trust_public_key)

    if verbose:
        section("Evidence integrity")
        kv("Trust anchor", "supplied independently of the ledger")
        kv("Result", "VERIFIED" if integrity["valid"] else f"FAILED ({integrity['failure']})")
        kv("Events checked", integrity["checked"])

        section("Control validation")
        print(f"{'Control':<8}{'Result':<12}{'Title'}")
        rule()
        for c in results:
            print(f"{c.control_id:<8}{c.result:<12}{c.title}")
        print()
        for c in results:
            print(f"  {c.control_id} {c.result}")
            print(f"    {c.detail}")

    return {"env": env, "session": session, "reconstruction": r, "controls": results,
            "integrity": integrity}


def main() -> None:
    run()


if __name__ == "__main__":
    main()
