"""
Scenario 1 - Normal authorized operation.

A research agent makes a legitimate request for internal research data. The
security architecture must not break ordinary work: identity is validated,
policy is evaluated, the action is authorized, it executes, and the whole
sequence is recorded as evidence.

The output deliberately separates three distinct things that are easy to
conflate when reading a transcript:

    Authorization   the security decision
    Tool execution  whether the brokered call ran, and against what
    Tool response   the data the mock backend returned

A second call exercises output screening: the document repository stub returns
an excerpt containing a synthetic identifier, which is detected and redacted
before it reaches the agent.

All backend responses are fabricated. No system is contacted.
"""

from __future__ import annotations

from scenarios._common import Environment, banner, block, build_environment, kv, section


def run(env: Environment | None = None, verbose: bool = True) -> dict:
    env = env or build_environment("normal_request")
    session = env.new_session("researcher-023")

    if verbose:
        banner("SCENARIO 1", "Normal authorized operation")
        kv("User", "researcher-023")
        kv("Agent", session.agent_id)
        kv("Identity", session.claims["sub"])
        kv("Role", session.claims["role"])
        kv("Credential scope", ", ".join(session.claims["scope"]))

    search = session.request_tool("clinical.search", purpose="research-summary")

    if verbose:
        section("Authorization")
        kv("Tool", search.tool)
        kv("Policy", search.policy_id)
        kv("Decision", "ALLOW" if search.decision.allowed else "DENY")

        section("Tool execution")
        kv("Status", search.status.upper())
        kv("System", search.decision.evaluation_input["resource"]["system"])
        kv("Classification", search.decision.evaluation_input["resource"]["classification"])
        kv("Data source", "Synthetic mock backend (no system contacted)")

        section("Tool response")
        block("Returned", search.output)

    summarize = session.request_tool("documents.summarize", purpose="research-summary")
    session.close()

    if verbose:
        section("Authorization")
        kv("Tool", summarize.tool)
        kv("Policy", summarize.policy_id)
        kv("Decision", "ALLOW" if summarize.decision.allowed else "DENY")

        section("Output screening")
        kv("Sensitive findings", len(summarize.dlp_findings))
        kv("Categories", ", ".join(f["category"] for f in summarize.dlp_findings) or "none")
        kv("Action", "REDACT" if summarize.redacted else "none")

        section("Sanitized tool response")
        kv("Data source", "Synthetic mock backend (no system contacted)")
        block("Returned", summarize.output)

        print()
        print("Authorization, execution and returned data are separate concerns.")
        print("Legitimate work continues to function under the security boundary.")

    return {"env": env, "session": session, "results": [search, summarize]}


def main() -> None:
    run()


if __name__ == "__main__":
    main()
