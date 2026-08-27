"""Shared environment construction and console formatting for scenarios."""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path

from agents.research_agent import ResearchAgentSession
from forensics.evidence import EvidenceLedger, LedgerSigner
from gateway.authorization import AuthorizationEngine
from gateway.identity import IdentityProvider
from gateway.tool_broker import ToolBroker

REPO_ROOT = Path(__file__).resolve().parent.parent
RUN_DIR = REPO_ROOT / "run"

WIDTH = 66


@dataclass
class Environment:
    """A gateway, its evidence ledger, and the independently held trust key."""

    ledger: EvidenceLedger
    identity: IdentityProvider
    broker: ToolBroker
    trust_public_key: bytes
    run_dir: Path

    def new_session(self, user_id: str, **kwargs) -> ResearchAgentSession:
        return ResearchAgentSession(
            self.ledger, self.identity, self.broker, user_id, **kwargs
        )


def build_environment(name: str = "scenario", clean: bool = True) -> Environment:
    run_dir = RUN_DIR / name
    if clean and run_dir.exists():
        shutil.rmtree(run_dir)
    run_dir.mkdir(parents=True, exist_ok=True)

    signer = LedgerSigner.generate()
    signer.save(run_dir / "keys" / "ledger_ed25519.pem")

    # The trust anchor is captured at provisioning time and held by the
    # verifier. Verification never reads a key from beside the evidence.
    trust_public_key = signer.public_key_pem()
    (run_dir / "trust_anchor.pub").write_bytes(trust_public_key)

    ledger = EvidenceLedger(run_dir / "evidence.log", signer=signer)
    identity = IdentityProvider()
    broker = ToolBroker(ledger, identity, AuthorizationEngine())
    return Environment(ledger, identity, broker, trust_public_key, run_dir)


def rule(char: str = "-") -> None:
    print(char * WIDTH)


def banner(title: str, subtitle: str = "") -> None:
    print()
    rule("=")
    print(title)
    if subtitle:
        print(subtitle)
    rule("=")


def section(title: str) -> None:
    print()
    print(title)
    rule("-")


def kv(label: str, value, width: int = 22) -> None:
    print(f"{label + ':':<{width}}{value}")
