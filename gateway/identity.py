"""
Agent workload identity.

Agents are workloads, not users. An agent does not inherit the privileges of
the human who prompted it. Each agent session receives:

  * a distinct workload identity (SPIFFE-style URI);
  * a short-lived credential minted per session;
  * a role and an explicitly enumerated capability scope;
  * a binding to the session it was minted for.

A credential minted for one session is rejected in another, so a leaked
credential does not become a general-purpose key to the agent's capabilities.

Scope: this is a compact demonstration of the properties that matter at the
authorization boundary, not a production IdP. Credentials are HMAC-tagged
rather than asymmetrically signed, which means the verifier could also mint;
a production deployment would use a real workload identity system (SPIFFE
/SPIRE, cloud workload identity federation) with asymmetric signing.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time

DEFAULT_TTL_SECONDS = 900  # 15 minutes


class IdentityError(Exception):
    """Raised when a credential fails validation.

    Carries a machine-readable ``reason`` so the enforcement boundary can
    record a specific failure as security evidence rather than swallowing it.
    """

    def __init__(self, reason: str, message: str):
        super().__init__(message)
        self.reason = reason
        self.message = message


# Registered agent workloads. Each is a distinct identity with its own role
# and its own least-privilege capability set.
WORKLOAD_REGISTRY = {
    "agent:research-reader": {
        "spiffe_id": "spiffe://ai-agents.internal/research-reader",
        "role": "research_reader",
        "capabilities": ["clinical.search", "documents.summarize"],
    },
    "agent:ops-analyst": {
        "spiffe_id": "spiffe://ai-agents.internal/ops-analyst",
        "role": "ops_reader",
        "capabilities": ["erp.query", "manufacturing.status"],
    },
}


class IdentityProvider:
    def __init__(self, secret: bytes | None = None, ttl_seconds: int = DEFAULT_TTL_SECONDS):
        self._secret = secret or os.urandom(32)
        self.ttl_seconds = ttl_seconds
        self.registry = {k: dict(v) for k, v in WORKLOAD_REGISTRY.items()}

    def mint(
        self,
        agent_id: str,
        session_id: str,
        scope_override: list[str] | None = None,
    ) -> dict:
        """Mint a short-lived, session-bound, scope-limited credential.

        ``scope_override`` exists so a scenario can deliberately mint an
        over-broad credential and demonstrate that the classification policy
        still contains the action. It is never used on a normal path.
        """
        if agent_id not in self.registry:
            raise IdentityError("unknown_workload", f"unknown workload identity: {agent_id}")
        profile = self.registry[agent_id]
        issued = int(time.time())
        claims = {
            "sub": profile["spiffe_id"],
            "agent_id": agent_id,
            "role": profile["role"],
            "scope": list(scope_override if scope_override is not None else profile["capabilities"]),
            "sid": session_id,
            "iat": issued,
            "exp": issued + self.ttl_seconds,
        }
        body = base64.urlsafe_b64encode(json.dumps(claims, sort_keys=True).encode("utf-8")).decode("ascii")
        tag = hmac.new(self._secret, body.encode("ascii"), hashlib.sha256).hexdigest()
        return {"credential": f"{body}.{tag}", "claims": claims}

    def validate(self, credential: str, session_id: str) -> dict:
        """Validate a credential and bind it to the session presenting it.

        Raises IdentityError with a specific reason on every failure path so
        the caller can record it as evidence.
        """
        # Every malformed input must leave by the IdentityError path. An
        # uncaught exception here would escape the broker before it can record
        # the attempt, and an unrecorded attempt is indistinguishable from no
        # attempt at all.
        if not isinstance(credential, str):
            raise IdentityError("malformed", "credential is not a string")

        try:
            body, tag = credential.rsplit(".", 1)
        except ValueError:
            raise IdentityError("malformed", "credential is not well-formed")

        try:
            body_bytes = body.encode("ascii")
        except UnicodeEncodeError:
            raise IdentityError("malformed", "credential contains non-ASCII characters")

        expected = hmac.new(self._secret, body_bytes, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(tag, expected):
            raise IdentityError("bad_signature", "credential signature is invalid")

        try:
            claims = json.loads(base64.urlsafe_b64decode(body))
        except Exception:
            raise IdentityError("malformed", "credential claims are not decodable")

        if claims.get("agent_id") not in self.registry:
            raise IdentityError("unknown_workload", "credential names an unregistered workload")

        if claims.get("exp", 0) <= time.time():
            raise IdentityError("expired", "credential has expired")

        # Session binding: a credential minted for one session is not usable
        # in another, even though it is otherwise cryptographically intact.
        if claims.get("sid") != session_id:
            raise IdentityError(
                "session_mismatch",
                "credential was minted for a different session",
            )

        return claims
