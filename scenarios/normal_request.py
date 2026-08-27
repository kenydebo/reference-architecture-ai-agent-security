"""
Scenario 1 - Normal authorized operation.

A research agent makes a legitimate request for internal research data. The
security architecture must not break ordinary work: identity is validated,
policy is evaluated, the action is authorized, it executes, and the whole
sequence is recorded as evidence.

This scenario also exercises output screening: the R&D document repository
returns an excerpt containing a synthetic identifier, which is detected and
redacted before it reaches the agent.
"""

from __future__ import annotations

from scenarios._common import Environment, banner, build_environment, kv, section


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
    summarize = session.request_tool("documents.summarize", purpose="research-summary")
    session.close()

    if verbose:
        section("Authorization")
        kv("Tool", search.tool)
        kv("Policy", search.policy_id)
        kv("Decision", "ALLOW" if search.status == "completed" else search.status.upper())
        kv("Result", search.output)

        section("Output screening")
        kv("Tool", summarize.tool)
        kv("Decision", "ALLOW")
        kv("Sensitive findings", len(summarize.dlp_findings))
        kv("Output redacted", summarize.redacted)
        kv("Result", summarize.output)

        print()
        print("Legitimate work continues to function under the security boundary.")

    return {"env": env, "session": session, "results": [search, summarize]}


def main() -> None:
    run()


if __name__ == "__main__":
    main()
