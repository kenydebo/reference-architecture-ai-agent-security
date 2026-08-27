"""
Scenario 3 - Misconfigured / overprivileged credential.

Defense in depth. The research agent is deliberately minted a credential whose
capability scope wrongly includes clinical_data.export, as would happen through
a provisioning mistake or an over-broad role definition.

The least-privilege control therefore does NOT deny: the action is inside the
credential's scope. The request still fails, because the classification rule
evaluates the role against the data classification of the target resource and
denies independently.

The demonstration is that a single misconfigured identity scope does not
produce unrestricted access.
"""

from __future__ import annotations

from scenarios._common import Environment, banner, build_environment, kv, section

OVERBROAD_SCOPE = ["clinical.search", "documents.summarize", "clinical_data.export"]


def run(env: Environment | None = None, verbose: bool = True) -> dict:
    env = env or build_environment("overprivileged_token")
    session = env.new_session("researcher-023", scope_override=OVERBROAD_SCOPE)

    if verbose:
        banner("SCENARIO 3", "Misconfigured / overprivileged credential")
        kv("Agent", session.agent_id)
        kv("Role", session.claims["role"])
        print()
        print("  Credential scope as minted (misconfigured):")
        for cap in session.claims["scope"]:
            marker = "   <-- should not be here" if cap == "clinical_data.export" else ""
            print(f"    - {cap}{marker}")

    result = session.request_tool("clinical_data.export", purpose="cross-reference")
    session.close()

    decision = result.decision
    scope_denied = decision.denied_by("AI-IAM-004")
    classification_denied = decision.denied_by("AI-DATA-004")

    if verbose:
        section("Control-by-control outcome")
        kv("AI-IAM-004 least privilege", "did not deny (action is in scope)" if not scope_denied else "DENIED", 30)
        kv("AI-DATA-004 classification", "DENIED" if classification_denied else "did not deny", 30)
        print()
        for d in decision.deny_reasons:
            print(f"  - {d.policy_id} [{d.control}]")
            print(f"    {d.reason}")

        section("Result")
        kv("Decision", "DENY" if result.status == "denied" else result.status.upper(), 30)
        kv("Incident", result.incident_id, 30)
        kv("Defense in depth", "PASS" if classification_denied and not scope_denied else "NOT DEMONSTRATED", 30)
        print()
        print("The capability-scope control was defeated by misconfiguration.")
        print("The classification control contained the action on its own.")

    return {
        "env": env,
        "session": session,
        "result": result,
        "scope_denied": scope_denied,
        "classification_denied": classification_denied,
    }


def main() -> None:
    run()


if __name__ == "__main__":
    main()
