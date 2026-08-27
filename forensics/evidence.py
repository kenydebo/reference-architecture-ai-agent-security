"""
Security evidence ledger: append-only, hash-chained, signed.

Design
------
Every security-relevant decision made at the enforcement boundary is appended
as a ledger entry. Each entry carries the SHA-256 hash of the previous entry,
so modification, insertion, removal or reordering of any interior entry breaks
every subsequent link. Each entry hash is signed with Ed25519.

Trust anchor
------------
Verification is a module-level function that REQUIRES the caller to supply the
trusted public key. It is deliberately not a method on the ledger, and the
ledger never offers its own key for verification: an investigator who obtained
the trust key from the ledger's own directory would detect nothing if an
attacker replaced the key and re-signed the history.

Scope and limitations are documented in architecture/architecture.md. The two
that matter most:

  * Tail truncation is NOT detectable by this construction alone. A chain links
    backwards, so nothing commits to the existence of the next entry. Pass
    ``expected_head`` to verify_ledger() when an independently retained chain
    head is available; production systems anchor that head externally.
  * An empty ledger is reported as NO_EVIDENCE, never as a successful
    integrity assessment.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterator

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

GENESIS_HASH = "0" * 64
ENCODING = "utf-8"


def _canonical(obj: Any) -> bytes:
    """Deterministic JSON serialization for hashing and signing."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode(ENCODING)


def _utc_now() -> str:
    # Single clock read, so the millisecond field always belongs to the second
    # field it is printed beside.
    now = time.time()
    stamp = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(now))
    return f"{stamp}.{int((now % 1) * 1000):03d}Z"


@dataclass
class LedgerEntry:
    seq: int
    event_id: str
    timestamp: str
    session_id: str
    event_type: str
    actor: dict
    payload: dict
    prev_hash: str
    event_hash: str = ""
    signature: str = ""

    def signing_view(self) -> dict:
        d = asdict(self)
        d.pop("event_hash")
        d.pop("signature")
        return d


class LedgerSigner:
    """Holds the Ed25519 signing key. Owned by the gateway, never by the agent."""

    def __init__(self, private_key: Ed25519PrivateKey):
        self._private_key = private_key

    @classmethod
    def generate(cls) -> "LedgerSigner":
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def load(cls, path: str | os.PathLike) -> "LedgerSigner":
        data = Path(path).read_bytes()
        return cls(serialization.load_pem_private_key(data, password=None))

    def save(self, path: str | os.PathLike) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(
            self._private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        os.chmod(p, 0o600)

    def public_key_pem(self) -> bytes:
        """Export the trust anchor for independent distribution to verifiers."""
        return self._private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def sign(self, message: bytes) -> str:
        return self._private_key.sign(message).hex()


class EvidenceLedger:
    """Append-only, hash-chained, signed security evidence log."""

    def __init__(self, path: str | os.PathLike, signer: LedgerSigner):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._signer = signer
        self._seq, self._last_hash = self._recover_head()

    def _recover_head(self) -> tuple[int, str]:
        last = None
        for entry in self.entries():
            last = entry
        if last is None:
            return 0, GENESIS_HASH
        return last["seq"] + 1, last["event_hash"]

    @property
    def head(self) -> str:
        """Current chain head. Retain this independently to detect truncation."""
        return self._last_hash

    def append(
        self, session_id: str, event_type: str, actor: dict, payload: dict
    ) -> LedgerEntry:
        entry = LedgerEntry(
            seq=self._seq,
            event_id=f"evt-{uuid.uuid4().hex[:12]}",
            timestamp=_utc_now(),
            session_id=session_id,
            event_type=event_type,
            actor=actor,
            payload=payload,
            prev_hash=self._last_hash,
        )
        entry.event_hash = hashlib.sha256(_canonical(entry.signing_view())).hexdigest()
        entry.signature = self._signer.sign(entry.event_hash.encode(ENCODING))

        with open(self.path, "a", encoding=ENCODING) as f:
            f.write(json.dumps(asdict(entry)) + "\n")

        self._seq += 1
        self._last_hash = entry.event_hash
        return entry

    def entries(self) -> Iterator[dict]:
        if not self.path.exists():
            return
        with open(self.path, encoding=ENCODING) as f:
            for line in f:
                if line.strip():
                    yield json.loads(line)

    def session(self, session_id: str) -> list[dict]:
        return [e for e in self.entries() if e["session_id"] == session_id]


def load_trust_key(pem: bytes) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(pem)
    if not isinstance(key, Ed25519PublicKey):
        raise TypeError("trust anchor must be an Ed25519 public key")
    return key


def verify_ledger(
    path: str | os.PathLike,
    trust_public_key: Ed25519PublicKey | bytes,
    expected_head: str | None = None,
) -> dict:
    """Independently verify a ledger against a separately supplied trust anchor.

    The trust key is a required argument by design. Verification that sourced
    its key from beside the evidence would accept a wholesale re-signed
    history, which is not a meaningful integrity assessment.
    """
    if isinstance(trust_public_key, (bytes, bytearray)):
        trust_public_key = load_trust_key(bytes(trust_public_key))

    def fail(failure: str, detail: str, checked: int, at_seq: int | None = None) -> dict:
        return {
            "valid": False,
            "checked": checked,
            "failure": failure,
            "at_seq": at_seq,
            "detail": detail,
        }

    prev = GENESIS_HASH
    checked = 0
    last_hash = None

    p = Path(path)
    if not p.exists():
        return fail("NO_EVIDENCE", "no evidence file exists at this path", 0)

    with open(p, encoding=ENCODING) as f:
        for line in f:
            if not line.strip():
                continue
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                return fail("MALFORMED_ENTRY", "entry is not valid JSON", checked)

            view = {k: v for k, v in e.items() if k not in ("event_hash", "signature")}
            if e["prev_hash"] != prev:
                return fail(
                    "CHAIN_BREAK",
                    "prev_hash does not match the preceding entry hash "
                    "(entry inserted, removed or reordered)",
                    checked,
                    e["seq"],
                )
            if hashlib.sha256(_canonical(view)).hexdigest() != e["event_hash"]:
                return fail(
                    "CONTENT_TAMPERED",
                    "entry content does not match its recorded hash",
                    checked,
                    e["seq"],
                )
            try:
                trust_public_key.verify(
                    bytes.fromhex(e["signature"]), e["event_hash"].encode(ENCODING)
                )
            except Exception:
                return fail(
                    "BAD_SIGNATURE",
                    "signature does not verify under the supplied trust anchor "
                    "(re-signed with an unauthorized key, or forged)",
                    checked,
                    e["seq"],
                )
            prev = e["event_hash"]
            last_hash = e["event_hash"]
            checked += 1

    if checked == 0:
        return fail("NO_EVIDENCE", "evidence file contains no entries", 0)

    if expected_head is not None and last_hash != expected_head:
        return fail(
            "TRUNCATED",
            "chain head does not match the independently retained head "
            "(entries removed from the end of the log)",
            checked,
        )

    return {
        "valid": True,
        "checked": checked,
        "failure": None,
        "at_seq": None,
        "detail": "hash chain continuous and every signature verified",
        "head": last_hash,
    }
