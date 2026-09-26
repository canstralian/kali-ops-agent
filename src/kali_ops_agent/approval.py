"""HMAC-SHA256 approval tokens for actions gated on explicit human sign-off.

A high-impact action is not executed on the caller's say-so alone: the core
issues a *challenge* describing exactly what would run, an approver signs that
challenge with the engagement's shared secret, and the core verifies the
signature before proceeding. Tokens are single-purpose (bound to the exact
request payload), time-boxed, and single-use: each challenge carries a random
nonce that ``verify`` consumes on first success, so one sign-off authorizes one
execution and a captured token cannot be replayed within its TTL.

The secret never travels over the tool surface. It is provisioned out of band
(e.g. an environment variable read by the deployer) and used only to mint and
verify tokens.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import threading
import time
from dataclasses import dataclass

from .errors import ApprovalError


def _canonical_challenge(payload: dict[str, object]) -> bytes:
    """Deterministic byte encoding so signer and verifier agree exactly."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass
class ApprovalConfig:
    ttl_seconds: int = 300

    def __post_init__(self) -> None:
        if self.ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")


class ApprovalAuthority:
    """Mints and verifies approval tokens bound to a specific action payload."""

    def __init__(
        self,
        secret: bytes,
        config: ApprovalConfig | None = None,
        *,
        clock=time.time,
    ) -> None:
        if not secret:
            raise ValueError("approval secret must be non-empty")
        self._secret = secret
        self._config = config or ApprovalConfig()
        self._clock = clock
        # nonce -> expires_at, so a consumed token cannot be replayed until it
        # would have expired anyway. Guarded by a lock for concurrent verifies.
        self._used: dict[str, int] = {}
        self._used_lock = threading.Lock()

    def challenge(self, action: dict[str, object]) -> dict[str, object]:
        """Build the payload an approver must sign for ``action``."""
        issued = int(self._clock())
        return {
            "action": action,
            "nonce": secrets.token_hex(16),
            "issued_at": issued,
            "expires_at": issued + self._config.ttl_seconds,
        }

    def sign(self, challenge: dict[str, object]) -> str:
        """Produce the HMAC token for a challenge (approver side)."""
        mac = hmac.new(self._secret, _canonical_challenge(challenge), hashlib.sha256)
        return mac.hexdigest()

    def verify(self, challenge: dict[str, object], token: str) -> None:
        """Verify a token against its challenge, fail closed on any mismatch.

        Raises:
            ApprovalError: if the token is malformed, forged, or expired.
        """
        expected = self.sign(challenge)
        if not hmac.compare_digest(expected, token or ""):
            raise ApprovalError("approval token signature is invalid")
        expires_at = challenge.get("expires_at")
        if not isinstance(expires_at, int):
            raise ApprovalError("approval challenge is missing a valid expiry")
        now = self._clock()
        if now > expires_at:
            raise ApprovalError("approval token has expired")
        nonce = challenge.get("nonce")
        if not isinstance(nonce, str) or not nonce:
            raise ApprovalError("approval challenge is missing a valid nonce")
        # Single-use: atomically reject an already-consumed nonce and record
        # this one. A token is still acceptable at exactly expires_at (the
        # expiry check above uses ``>``), so a consumed nonce must be retained
        # while ``exp >= now`` — purging with ``> now`` would drop it at that
        # instant and allow one replay at the boundary.
        with self._used_lock:
            self._used = {n: exp for n, exp in self._used.items() if exp >= now}
            if nonce in self._used:
                raise ApprovalError("approval token has already been used")
            self._used[nonce] = expires_at
