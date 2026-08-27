"""Authorization: allow, deny precedence, default deny, and the classification backstop."""

from __future__ import annotations

import itertools

import pytest

from gateway.authorization import (
    CLASSIFICATION_RULES,
    RESOURCE_CATALOG,
    ROLE_GRANTS,
    AuthorizationEngine,
)
from tests.conftest import claims_for

RESEARCH_SCOPE = ["clinical.search", "documents.summarize"]
OVERBROAD_SCOPE = RESEARCH_SCOPE + ["clinical_data.export"]


# ----------------------------------------------------------------- allow

@pytest.mark.parametrize("tool", ["clinical.search", "documents.summarize"])
def test_permitted_research_action_is_allowed(authorizer, tool):
    d = authorizer.evaluate(claims_for(scope=RESEARCH_SCOPE), tool, "research-summary")
    assert d.allowed is True
    assert d.policy_id == "AI-DATA-001"
    assert d.deny_reasons == []


def test_ops_role_is_allowed_its_own_tools(authorizer):
    d = authorizer.evaluate(
        claims_for(role="ops_reader", scope=["erp.query", "manufacturing.status"],
                   agent_id="agent:ops-analyst"),
        "erp.query", "ops-report",
    )
    assert d.allowed is True
    assert d.policy_id == "AI-DATA-002"


# ------------------------------------------------------------------ deny

def test_restricted_export_is_denied_with_normal_scope(authorizer):
    d = authorizer.evaluate(claims_for(scope=RESEARCH_SCOPE), "clinical_data.export", "x")
    assert d.allowed is False
    # Two independent controls deny this request.
    assert d.denied_by("AI-DATA-004")
    assert d.denied_by("AI-IAM-004")


def test_unknown_tool_is_default_denied(authorizer):
    d = authorizer.evaluate(claims_for(), "clinicl.serch", "typo")
    assert d.allowed is False
    assert d.policy_id == "AI-DEFAULT-DENY"


def test_wrong_role_cannot_use_another_roles_tool(authorizer):
    d = authorizer.evaluate(
        claims_for(role="ops_reader", scope=["erp.query"], agent_id="agent:ops-analyst"),
        "clinical.search", "x",
    )
    assert d.allowed is False


def test_scope_alone_is_not_authorization(authorizer):
    """A tool inside the credential scope still needs an explicit role grant.

    erp.query is internal-classification, so no classification rule fires and
    the scope check passes -- yet the research role has no grant for it.
    """
    d = authorizer.evaluate(
        claims_for(role="research_reader", scope=["erp.query"]), "erp.query", "x"
    )
    assert d.allowed is False
    assert d.denied_by("AI-DEFAULT-DENY")
    assert not d.denied_by("AI-IAM-004")  # it was in scope


# ------------------------------------------------- classification backstop

def test_overprivileged_scope_does_not_grant_restricted_export(authorizer):
    """The scenario-3 property: misconfigured scope, still contained."""
    d = authorizer.evaluate(claims_for(scope=OVERBROAD_SCOPE), "clinical_data.export", "x")
    assert d.allowed is False
    assert d.denied_by("AI-DATA-004")
    # The least-privilege control did NOT deny -- the backstop carried it alone.
    assert not d.denied_by("AI-IAM-004")


def test_classification_rule_denies_all_restricted_classifications(authorizer):
    d = authorizer.evaluate(
        claims_for(scope=["manufacturing.batch_records"]), "manufacturing.batch_records", "x"
    )
    assert d.allowed is False
    assert d.denied_by("AI-DATA-004")


def test_classification_rule_is_reachable_and_not_dead_code():
    """Guards against the scope check short-circuiting the backstop."""
    engine = AuthorizationEngine()
    restricted = [
        t for t, r in RESOURCE_CATALOG.items() if r["classification"].startswith("restricted")
    ]
    assert restricted, "fixture requires at least one restricted resource"
    for tool in restricted:
        d = engine.evaluate(claims_for(scope=[tool]), tool, "x")
        assert d.denied_by("AI-DATA-004"), f"classification rule never fired for {tool}"


# ---------------------------------------------------------- never fail open

def test_no_role_scope_combination_authorizes_restricted_data():
    """Exhaustive sweep: nothing reaches a restricted resource, however scoped."""
    engine = AuthorizationEngine()
    roles = ["research_reader", "ops_reader"]
    restricted = [
        t for t, r in RESOURCE_CATALOG.items() if r["classification"].startswith("restricted")
    ]
    for role, tool in itertools.product(roles, restricted):
        for scope in ([], [tool], list(RESOURCE_CATALOG)):
            d = engine.evaluate(claims_for(role=role, scope=scope), tool, "x")
            assert d.allowed is False, f"{role} was allowed {tool} with scope {scope}"


def test_every_allow_is_backed_by_an_explicit_grant():
    """No decision may be ALLOW without a matching role grant and in-scope action."""
    engine = AuthorizationEngine()
    for role in ["research_reader", "ops_reader"]:
        for tool in list(RESOURCE_CATALOG) + ["unknown.tool"]:
            d = engine.evaluate(
                claims_for(role=role, scope=list(RESOURCE_CATALOG)), tool, "x"
            )
            if d.allowed:
                grant = next(g for g in ROLE_GRANTS if g["id"] == d.policy_id)
                assert grant["role"] == role
                assert tool in grant["allow_tools"]
                assert RESOURCE_CATALOG[tool]["classification"] == "internal"


def test_empty_scope_denies_everything():
    engine = AuthorizationEngine()
    for tool in RESOURCE_CATALOG:
        assert engine.evaluate(claims_for(scope=[]), tool, "x").allowed is False


def test_decision_records_the_evaluation_input(authorizer):
    """Evidence must carry the attributes the decision was made on."""
    d = authorizer.evaluate(claims_for(scope=RESEARCH_SCOPE), "clinical_data.export", "why")
    ev = d.evaluation_input
    assert ev["action"] == "clinical_data.export"
    assert ev["resource"]["classification"] == "restricted_phi"
    assert ev["agent"]["role"] == "research_reader"
    assert ev["credential_scope"] == RESEARCH_SCOPE
    assert ev["purpose"] == "why"


def test_classification_rules_cover_every_restricted_resource():
    """A restricted resource with no rule covering any role would be a gap."""
    covered = {c for rule in CLASSIFICATION_RULES for c in rule["deny_classifications"]}
    for tool, resource in RESOURCE_CATALOG.items():
        if resource["classification"].startswith("restricted"):
            assert resource["classification"] in covered, f"{tool} has no classification rule"
