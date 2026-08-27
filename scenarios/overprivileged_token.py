"""
Scenario 3 - Dual authorization misconfiguration / classification backstop.

Defense in depth, demonstrated rather than asserted.

Two independent authorization configuration failures are simulated at once:

  1. The research agent's credential scope wrongly includes
     clinical_data.export, so the least-privilege control does not deny.
  2. The role grant for research_reader wrongly includes clinical_data.export,
     so the explicit-authorization control does not deny either.

With both of the usual controls permitting the action, only the data
classification rule remains. The resource is restricted_phi and the acting
role is research_reader, so AI-DATA-004 denies independently.

The scenario computes the counterfactual explicitly: the same request is
re-evaluated against a policy with the classification rule removed, and it is
authorized. That is what makes "AI-DATA-004 is the load-bearing control" a
statement backed by evaluation rather than by prose. The same property is
asserted in tests/test_authorization.py.

The misconfigured policy is injected into a scenario-local authorization
engine bound to a scenario-local broker. Neither the reference policy
configuration nor the shared broker is mutated, so no scenario that runs after
this one evaluates against the misconfiguration.
"""

from __future__ import annotations

from copy import deepcopy

from gateway.authorization import (
    CONTROL_CAPABILITY_SCOPE,
    CONTROL_DATA_CLASSIFICATION,
    CONTROL_ROLE_GRANT,
    ROLE_GRANTS,
    AuthorizationEngine,
)
from gateway.tool_broker import ToolBroker
from scenarios._common import Environment, banner, build_environment, kv, rule, section

RESTRICTED_TOOL = "clinical_data.export"
OVERBROAD_SCOPE = ["clinical.search", "documents.summarize", RESTRICTED_TOOL]


def misconfigured_role_grants() -> list[dict]:
    """A copy of the reference grants with clinical_data.export wrongly added."""
    grants = deepcopy(ROLE_GRANTS)
    research = next(g for g in grants if g["role"] == "research_reader")
    research["allow_tools"] = research["allow_tools"] + [RESTRICTED_TOOL]
    research["description"] = (
        "MISCONFIGURED: research agents were incorrectly granted the export action."
    )
    return grants


def run(env: Environment | None = None, verbose: bool = True) -> dict:
    env = env or build_environment("overprivileged_token")

    # Scenario-local policy: both ordinary controls misconfigured to permit.
    # The misconfigured engine is bound to a scenario-local broker; the shared
    # broker and the reference configuration are never mutated.
    grants = misconfigured_role_grants()
    misconfigured = AuthorizationEngine(role_grants=grants)
    broker = ToolBroker(env.ledger, env.identity, misconfigured)

    session = env.new_session(
        "researcher-023", broker=broker, scope_override=OVERBROAD_SCOPE
    )

    if verbose:
        banner("SCENARIO 3", "Dual authorization misconfiguration / classification backstop")
        kv("Agent", session.agent_id, 26)
        kv("Role", session.claims["role"], 26)

        section("Misconfiguration 1 - credential scope")
        for cap in session.claims["scope"]:
            mark = "   <-- incorrectly included" if cap == RESTRICTED_TOOL else ""
            print(f"  {cap}{mark}")

        section("Misconfiguration 2 - role grant")
        research = next(g for g in grants if g["role"] == "research_reader")
        for tool in research["allow_tools"]:
            mark = "   <-- incorrectly granted" if tool == RESTRICTED_TOOL else ""
            print(f"  research_reader -> {tool}{mark}")

    result = session.request_tool(RESTRICTED_TOOL, purpose="cross-reference")
    session.close()
    decision = result.decision

    # The counterfactual, evaluated rather than claimed: same request, same
    # misconfigured grants, classification rules removed.
    without_classification = AuthorizationEngine(
        role_grants=grants, classification_rules=[]
    ).evaluate(session.claims, RESTRICTED_TOOL, "cross-reference")

    scope_ok = decision.control_passed(CONTROL_CAPABILITY_SCOPE)
    grant_ok = decision.control_passed(CONTROL_ROLE_GRANT)
    classification_denied = not decision.control_passed(CONTROL_DATA_CLASSIFICATION)
    load_bearing = scope_ok and grant_ok and classification_denied and without_classification.allowed

    if verbose:
        section("Authorization evaluation")
        for c in decision.control_results:
            label = {
                CONTROL_CAPABILITY_SCOPE: "Capability scope",
                CONTROL_DATA_CLASSIFICATION: "Data classification",
                CONTROL_ROLE_GRANT: "Explicit role grant",
            }[c.control]
            policy = c.policy_id or "-"
            print(f"  {policy:<16}{label:<24}{c.result}")

        print()
        kv("Resource classification", decision.evaluation_input["resource"]["classification"], 26)
        kv("Final decision", "DENY" if result.status == "denied" else result.status.upper(), 26)
        kv("Executed", "no", 26)
        kv("Incident", result.incident_id, 26)

        section("Counterfactual (evaluated, not asserted)")
        kv("With AI-DATA-004", "DENY" if not decision.allowed else "ALLOW", 26)
        kv("Without AI-DATA-004", "ALLOW" if without_classification.allowed else "DENY", 26)
        print()
        kv("Defense in depth", "PASS" if load_bearing else "NOT DEMONSTRATED", 26)
        print()
        print("Both ordinary authorization controls were misconfigured to permit")
        print("this action. The data-classification policy is the load-bearing")
        print("backstop: remove it and the same request is authorized.")

    return {
        "env": env,
        "session": session,
        "result": result,
        "scope_passed": scope_ok,
        "role_grant_passed": grant_ok,
        "classification_denied": classification_denied,
        "allowed_without_classification": without_classification.allowed,
        "load_bearing": load_bearing,
    }


def main() -> None:
    run()


if __name__ == "__main__":
    main()
