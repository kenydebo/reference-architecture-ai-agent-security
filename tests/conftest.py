"""Shared fixtures. Every test runs against an isolated ledger in tmp_path."""

from __future__ import annotations

import pytest

from agents.research_agent import ResearchAgentSession
from forensics.evidence import EvidenceLedger, LedgerSigner
from gateway.authorization import AuthorizationEngine
from gateway.identity import IdentityProvider
from gateway.tool_broker import ToolBroker


class Harness:
    def __init__(self, tmp_path):
        self.signer = LedgerSigner.generate()
        self.trust_key = self.signer.public_key_pem()
        self.path = tmp_path / "evidence.log"
        self.ledger = EvidenceLedger(self.path, signer=self.signer)
        self.identity = IdentityProvider()
        self.broker = ToolBroker(self.ledger, self.identity, AuthorizationEngine())

    def session(self, user_id="researcher-023", **kwargs) -> ResearchAgentSession:
        return ResearchAgentSession(
            self.ledger, self.identity, self.broker, user_id, **kwargs
        )


@pytest.fixture
def harness(tmp_path) -> Harness:
    return Harness(tmp_path)


@pytest.fixture
def authorizer() -> AuthorizationEngine:
    return AuthorizationEngine()


def claims_for(role="research_reader", scope=None, agent_id="agent:research-reader"):
    """Build a claims dict directly, for exercising the engine in isolation."""
    return {
        "agent_id": agent_id,
        "role": role,
        "scope": scope if scope is not None else ["clinical.search", "documents.summarize"],
        "sub": f"spiffe://ai-agents.internal/{agent_id.split(':')[-1]}",
    }
