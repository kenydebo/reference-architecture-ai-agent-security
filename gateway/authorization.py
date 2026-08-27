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


PASS = "PASS"
DENY = "DENY"

CONTROL_CAPABILITY_SCOPE = "capability_scope"
CONTROL_DATA_CLASSIFICATION = "data_classification"
CONTROL_ROLE_GRANT = "role_grant"


@dataclass
class DenyReason:
    policy_id: str
    control: str
    reason: str


@dataclass
class ControlEvaluation:
    """The verdict of one authorization control, whether it passed or denied.

    Recording passes as well as denials is what makes a defense-in-depth claim
    auditable: proving a rule was load-bearing requires evidence that the other
    controls would have permitted the action.
    """

    control: str
    policy_id: str
    result: str
    detail: str

    def as_dict(self) -> dict:
        return {
            "control": self.control,
            "policy_id": self.policy_id,
            "result": self.result,
            "detail": self.detail,
        }


@dataclass
class Decision:
    allowed: bool
    policy_id: str
    reason: str
    evaluation_input: dict
    deny_reasons: list[DenyReason] = field(default_factory=list)
    control_results: list[ControlEvaluation] = field(default_factory=list)

    @property
    def matched_policy_ids(self) -> list[str]:
        return [d.policy_id for d in self.deny_reasons]

    def denied_by(self, policy_id: str) -> bool:
        return any(d.policy_id == policy_id for d in self.deny_reasons)

    def control(self, control: str) -> ControlEvaluation | None:
        return next((c for c in self.control_results if c.control == control), None)

    def control_passed(self, control: str) -> bool:
        evaluation = self.control(control)
        return evaluation is not None and evaluation.result == PASS


class AuthorizationEngine:
    """Policy decision point.

    Policy configuration is injected rather than read from module globals, so a
    scenario or a test can evaluate a deliberately misconfigured policy without
    mutating the reference configuration that everything else uses.
    """

    def __init__(
        self,
        role_grants: list[dict] | None = None,
        classification_rules: list[dict] | None = None,
    ):
        self.role_grants = ROLE_GRANTS if role_grants is None else role_grants
        self.classification_rules = (
            CLASSIFICATION_RULES if classification_rules is None else classification_rules
        )

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

        # An unregistered resource cannot be authorized against.
        if resource is None:
            reason = f"unknown tool '{tool}' is not a registered resource"
            return Decision(
                allowed=False,
                policy_id=DEFAULT_DENY_ID,
                reason=reason,
                evaluation_input=evaluation_input,
                deny_reasons=[DenyReason(DEFAULT_DENY_ID, "default_deny", reason)],
                control_results=[
                    ControlEvaluation(CONTROL_ROLE_GRANT, DEFAULT_DENY_ID, DENY, reason)
                ],
            )

        classification = resource["classification"]
        controls: list[ControlEvaluation] = []
        deny_reasons: list[DenyReason] = []

        # --- Control 1: data classification. Deny precedence: evaluated first
        #     so it applies regardless of how the capability scope was minted.
        matched_rule = next(
            (
                r for r in self.classification_rules
                if role in r["roles"] and classification in r["deny_classifications"]
            ),
            None,
        )
        if matched_rule:
            detail = (
                f"role '{role}' may not act on classification '{classification}': "
                f"{matched_rule['description']}"
            )
            controls.append(
                ControlEvaluation(CONTROL_DATA_CLASSIFICATION, matched_rule["id"], DENY, detail)
            )
            deny_reasons.append(
                DenyReason(matched_rule["id"], CONTROL_DATA_CLASSIFICATION, detail)
            )
        else:
            controls.append(
                ControlEvaluation(
                    CONTROL_DATA_CLASSIFICATION,
                    "",
                    PASS,
                    f"no classification rule denies role '{role}' on '{classification}'",
                )
            )

        # --- Control 2: capability scope (least privilege).
        if tool not in scope:
            detail = f"action '{tool}' is outside the credential capability scope"
            controls.append(ControlEvaluation(CONTROL_CAPABILITY_SCOPE, SCOPE_RULE_ID, DENY, detail))
            deny_reasons.append(DenyReason(SCOPE_RULE_ID, CONTROL_CAPABILITY_SCOPE, detail))
        else:
            controls.append(
                ControlEvaluation(
                    CONTROL_CAPABILITY_SCOPE,
                    SCOPE_RULE_ID,
                    PASS,
                    f"action '{tool}' is inside the credential capability scope",
                )
            )

        # --- Control 3: explicit role grant. Scope alone is not authorization.
        granted = next(
            (g for g in self.role_grants if g["role"] == role and tool in g["allow_tools"]),
            None,
        )
        if granted is None:
            detail = f"no policy grants role '{role}' the action '{tool}'"
            controls.append(ControlEvaluation(CONTROL_ROLE_GRANT, DEFAULT_DENY_ID, DENY, detail))
            deny_reasons.append(DenyReason(DEFAULT_DENY_ID, CONTROL_ROLE_GRANT, detail))
        else:
            controls.append(
                ControlEvaluation(
                    CONTROL_ROLE_GRANT, granted["id"], PASS, granted["description"]
                )
            )

        if deny_reasons:
            primary = deny_reasons[0]
            return Decision(
                allowed=False,
                policy_id=primary.policy_id,
                reason=primary.reason,
                evaluation_input=evaluation_input,
                deny_reasons=deny_reasons,
                control_results=controls,
            )

        return Decision(
            allowed=True,
            policy_id=granted["id"],
            reason=granted["description"],
            evaluation_input=evaluation_input,
            deny_reasons=[],
            control_results=controls,
        )
