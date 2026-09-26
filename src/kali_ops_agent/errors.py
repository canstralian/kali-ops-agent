"""Typed exceptions for the governance layer.

Every governed operation fails *closed*: if authorization, scope, budget, or
approval cannot be positively established, the request is denied with one of
these exceptions rather than proceeding.
"""

from __future__ import annotations


class GovernanceError(Exception):
    """Base class for every fail-closed governance denial."""


class AuthorityError(GovernanceError):
    """The caller's authority tier is insufficient for the requested action."""


class ScopeError(GovernanceError):
    """The requested target is outside the authorized engagement scope."""


class ApprovalError(GovernanceError):
    """A required approval token is missing, malformed, expired, or forged."""


class RateLimitError(GovernanceError):
    """The caller has exhausted the token-bucket budget for this action."""


class AuditError(GovernanceError):
    """The audit log could not be written or its hash chain failed to verify."""
