"""
Research agent session.

A deliberately transparent agent: it authenticates a user, obtains a
session-bound workload credential, retrieves context, and asks the tool broker
to perform every action. It never touches an enterprise system directly.

The planner is deterministic. No model is called and no API key is required.
That is a scope decision, not a shortcut: the security claim this project makes
is about the enforcement boundary, and that boundary evaluates a requested
action identically whether the request originated from a language model, an
attacker-controlled planner, or faulty application logic. Simulating the
planner keeps the demonstration reproducible offline.

This project therefore makes no claim about real-model injection success rates,
jailbreak resistance, or retrieval ranking behaviour. See the README.
"""

from __future__ import annotations

import uuid
from pathlib import Path

from forensics.evidence import EvidenceLedger
from gateway.detection import scan_retrieved_document
from gateway.identity import IdentityProvider
from gateway.tool_broker import ToolBroker, ToolResult

DATA_DIR = Path(__file__).resolve().parent.parent / "data"


class ResearchAgentSession:
    def __init__(
        self,
        ledger: EvidenceLedger,
        identity_provider: IdentityProvider,
        broker: ToolBroker,
        user_id: str,
        agent_id: str = "agent:research-reader",
        scope_override: list[str] | None = None,
    ):
        self.ledger = ledger
        self.identity = identity_provider
        self.broker = broker
        self.user_id = user_id
        self.agent_id = agent_id
        self.session_id = f"sess-{uuid.uuid4().hex[:10]}"

        self.ledger.append(
            self.session_id,
            "user.authenticated",
            {"user": user_id},
            {"method": "sso", "mfa": True},
        )

        minted = self.identity.mint(agent_id, self.session_id, scope_override=scope_override)
        self.credential = minted["credential"]
        self.claims = minted["claims"]

        self.ledger.append(
            self.session_id,
            "agent.session_created",
            {"user": user_id, "agent": agent_id},
            {
                "spiffe_id": self.claims["sub"],
                "role": self.claims["role"],
                "credential_scope": self.claims["scope"],
                "credential_ttl_seconds": self.claims["exp"] - self.claims["iat"],
                "scope_is_overridden": scope_override is not None,
            },
        )

    def retrieve(self, query: str, corpus: str = "synthetic_research") -> list[dict]:
        """Retrieve context and screen each document for injection indicators.

        Retrieval is simulated by reading the whole synthetic corpus: this
        project does not model retrieval ranking, and makes no claim about it.
        """
        self.ledger.append(
            self.session_id,
            "rag.query",
            {"agent": self.agent_id},
            {"query": query, "corpus": corpus},
        )

        documents = []
        corpus_dir = DATA_DIR / corpus
        for path in sorted(corpus_dir.glob("*.txt")):
            text = path.read_text(encoding="utf-8")
            documents.append({"doc_id": path.name, "text": text})
            self.ledger.append(
                self.session_id,
                "rag.document_retrieved",
                {"agent": self.agent_id},
                {
                    "doc_id": path.name,
                    "chars": len(text),
                    "provenance": f"{corpus}/{path.name}",
                    "source_trust": "untrusted",
                },
            )
            for finding in scan_retrieved_document(path.name, text):
                self.ledger.append(
                    self.session_id,
                    "detection.injection_indicator",
                    {"component": "gateway.detection"},
                    finding,
                )
        return documents

    def request_tool(self, tool: str, purpose: str, args: dict | None = None) -> ToolResult:
        """Ask the broker to perform an action.

        Every agent path in this project goes through the broker. That is a
        routing property of this code, not an enforced one: production
        deployment needs process or network isolation so the agent runtime
        cannot reach a tool backend directly.
        """
        return self.broker.invoke(
            session_id=self.session_id,
            credential=self.credential,
            tool=tool,
            purpose=purpose,
            args=args,
        )

    def close(self) -> None:
        self.ledger.append(
            self.session_id,
            "agent.session_closed",
            {"agent": self.agent_id},
            {"user": self.user_id},
        )
