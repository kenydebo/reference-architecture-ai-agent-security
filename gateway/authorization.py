"""
Authorization (ABAC) for agent tool invocation.

Every consequential agent-to-tool action is evaluated here before the tool
broker will execute it. The agent is not trusted because it generated the
request; the request is evaluated on its attributes.

Decision inputs: agent identity, role, credential scope, requested action,
target resource, resource data classification, and purpose.

Evaluation order
----------------
  1. Unknown resource                -> default deny.
  2. Classification deny rules       -> deny precedence, evaluated first.
  3. Capability scope (least privilege).
  4. Explicit role grant.
  5. Default deny.

Every matched deny rule is collected rather than returning on the first. Two
independent controls denying the same request is a fact worth recording: it is
what makes the layering visible in evidence, and it is what lets a scenario
show that disabling one control does not open the path.

This Python engine is the executable reference implementation of the policy.
A production deployment would run an external policy decision point (OPA,
Cedar, or a cloud IAM policy engine); the evaluation input below is shaped as
a policy input document so it maps onto one directly.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Backing enterprise systems and the classification of the data they hold.
RESOURCE_CATALOG = {
    "clinical.search": {
        "system": "Clinical Research Database",
        "classification": "internal",
    },
    "documents.summarize": {
        "system": "R&D Document Repository",
        "classification": "internal",
    },
    "clinical_data.export": {
        "system": "Clinical Research Database",
        "classification": "restricted_phi",
    },
    "manufacturing.batch_records": {
        "system": "Manufacturing Quality System",
        "classification": "restricted",
    },
    "erp.query": {"system": "ERP", "classification": "internal"},
    "manufacturing.status": {
        "system": "Manufacturing Quality System",
        "classification": "internal",
    },
}

# Classification rules. These are the backstop: they hold even when a
# credential's capability scope has been misconfigured too broadly.
CLASSIFICATION_RULES = [
    {
        "id": "AI-DATA-004",
        "roles": ["research_reader"],
        "deny_classifications": ["restricted", "restricted_phi"],
        "description": "Research agents may not access restricted or PHI-classified data.",
    },
    {
        "id": "AI-DATA-005",
        "roles": ["ops_reader"],
        "deny_classifications": ["restricted_phi"],
        "description": "Operations agents may not access PHI-classified data.",
    },
]

# Role-to-capability grants. A capability in a credential's scope still needs
# an explicit grant for the role; scope alone is not authorization.
ROLE_GRANTS = [
    {
        "id": "AI-DATA-001",
        "role": "research_reader",
        "allow_tools": ["clinical.search", "documents.summarize"],
        "description": "Research agents may search and summarize internal research data.",
    },
    {
        "id": "AI-DATA-002",
        "role": "ops_reader",
        "allow_tools": ["erp.query", "manufacturing.status"],
        "description": "Operations agents may query internal ERP and manufacturing status.",
    },
]

SCOPE_RULE_ID = "AI-IAM-004"
DEFAULT_DENY_ID = "AI-DEFAULT-DENY"


@dataclass
class DenyReason:
    policy_id: str
    control: str
    reason: str


@dataclass
class Decision:
    allowed: bool
    policy_id: str
    reason: str
    evaluation_input: dict
    deny_reasons: list[DenyReason] = field(default_factory=list)

    @property
    def matched_policy_ids(self) -> list[str]:
        return [d.policy_id for d in self.deny_reasons]

    def denied_by(self, policy_id: str) -> bool:
        return any(d.policy_id == policy_id for d in self.deny_reasons)


class AuthorizationEngine:
    def evaluate(self, claims: dict, tool: str, purpose: str) -> Decision:
        resource = RESOURCE_CATALOG.get(tool)
        role = claims.get("role")
        scope = claims.get("scope", [])

        evaluation_input = {
            "agent": {"id": claims.get("agent_id"), "role": role, "spiffe_id": claims.get("sub")},
            "action": tool,
            "resource": resource or {"system": "unknown", "classification": "unknown"},
            "purpose": purpose,
            "credential_scope": scope,
        }

        # 1. Unknown resource: nothing can be authorized against it.
        if resource is None:
            reason = f"unknown tool '{tool}' is not a registered resource"
            return Decision(
                allowed=False,
                policy_id=DEFAULT_DENY_ID,
                reason=reason,
                evaluation_input=evaluation_input,
                deny_reasons=[DenyReason(DEFAULT_DENY_ID, "default_deny", reason)],
            )

        deny_reasons: list[DenyReason] = []

        # 2. Classification rules take precedence and are evaluated first, so
        #    they apply whether or not the capability scope was correct.
        for rule in CLASSIFICATION_RULES:
            if role in rule["roles"] and resource["classification"] in rule["deny_classifications"]:
                deny_reasons.append(
                    DenyReason(
                        rule["id"],
                        "data_classification",
                        f"role '{role}' may not act on classification "
                        f"'{resource['classification']}': {rule['description']}",
                    )
                )

        # 3. Least privilege: the action must be inside the credential's scope.
        if tool not in scope:
            deny_reasons.append(
                DenyReason(
                    SCOPE_RULE_ID,
                    "least_privilege",
                    f"action '{tool}' is outside the credential capability scope",
                )
            )

        # 4. Explicit role grant. Scope alone is not authorization.
        granted = next(
            (g for g in ROLE_GRANTS if g["role"] == role and tool in g["allow_tools"]),
            None,
        )
        if granted is None:
            deny_reasons.append(
                DenyReason(
                    DEFAULT_DENY_ID,
                    "default_deny",
                    f"no policy grants role '{role}' the action '{tool}'",
                )
            )

        # 5. Deny if any rule matched, otherwise allow under the explicit grant.
        if deny_reasons:
            primary = deny_reasons[0]
            return Decision(
                allowed=False,
                policy_id=primary.policy_id,
                reason=primary.reason,
                evaluation_input=evaluation_input,
                deny_reasons=deny_reasons,
            )

        return Decision(
            allowed=True,
            policy_id=granted["id"],
            reason=granted["description"],
            evaluation_input=evaluation_input,
            deny_reasons=[],
        )
