"""kali-ops-agent — a governance-first MCP framework for authorized purple-team ops.

This package ships the *control plane*, not offensive tooling: an authority
hierarchy, engagement scope validation with a hard block, token-bucket rate
limiting, HMAC approval tokens, and a tamper-evident audit log. Tool adapters are
templates you wire up for a specific, authorized engagement — every one of them
routed through :class:`GovernanceEngine` so no action bypasses the controls.
"""

from __future__ import annotations

from .approval import ApprovalAuthority, ApprovalConfig
from .audit import AuditEntry, AuditLog
from .config import EngagementConfig, load_approval_secret
from .engine import GovernanceEngine
from .errors import (
    ApprovalError,
    AuditError,
    AuthorityError,
    GovernanceError,
    RateLimitError,
    ScopeError,
)
from .models import (
    AuthorityTier,
    Decision,
    GovernanceResult,
    Principal,
    ToolRequest,
)
from .ratelimit import BucketConfig, TokenBucketLimiter
from .scope import ScopeGuard

__version__ = "0.1.0"

__all__ = [
    "ApprovalAuthority",
    "ApprovalConfig",
    "AuditEntry",
    "AuditLog",
    "AuthorityError",
    "AuthorityTier",
    "AuditError",
    "BucketConfig",
    "Decision",
    "EngagementConfig",
    "GovernanceEngine",
    "GovernanceError",
    "GovernanceResult",
    "Principal",
    "RateLimitError",
    "ScopeError",
    "ScopeGuard",
    "ApprovalError",
    "TokenBucketLimiter",
    "ToolRequest",
    "load_approval_secret",
    "__version__",
]
