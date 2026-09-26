"""The governance engine: the single choke point every tool call passes through.

Order of checks is deliberate and fail-closed at each step:

1. **Authority** — is the caller acting at a sufficient tier?
2. **Scope** — is the target provably inside the authorized engagement?
3. **Rate budget** — does the caller have budget left for this tool?
4. **Approval** — for approval-gated actions, is a valid token present?

Only if every check passes is ALLOW returned. Every outcome — allow or deny —
is written to the tamper-evident audit log before the verdict is handed back, so
there is no allowed action that is not also a recorded one.
"""

from __future__ import annotations

from .approval import ApprovalAuthority
from .audit import AuditLog
from .authority import require_min_tier
from .errors import ApprovalError, AuthorityError, RateLimitError, ScopeError
from .models import (
    AuthorityTier,
    Decision,
    GovernanceResult,
    Principal,
    ToolRequest,
)
from .ratelimit import TokenBucketLimiter
from .scope import ScopeGuard


class GovernanceEngine:
    """Coordinates authority, scope, rate, approval, and audit for one engagement."""

    def __init__(
        self,
        *,
        scope: ScopeGuard,
        limiter: TokenBucketLimiter,
        audit: AuditLog,
        approvals: ApprovalAuthority | None = None,
    ) -> None:
        self._scope = scope
        self._limiter = limiter
        self._audit = audit
        self._approvals = approvals

    def _record(
        self, principal: Principal, request: ToolRequest, decision: Decision, reason: str
    ) -> int:
        entry = self._audit.append(
            principal_id=principal.id,
            engagement_id=principal.engagement_id,
            tool=request.tool,
            target=request.target,
            action=request.action,
            decision=decision.value,
            reason=reason,
        )
        return entry.seq

    def evaluate(
        self,
        principal: Principal,
        request: ToolRequest,
        *,
        min_tier: AuthorityTier = AuthorityTier.USER,
        requires_approval: bool = False,
        approval_token: str | None = None,
        cost: float = 1.0,
    ) -> GovernanceResult:
        """Run the full check pipeline and return a recorded verdict."""
        # 1. Authority
        try:
            require_min_tier(principal, min_tier)
        except AuthorityError as exc:
            seq = self._record(principal, request, Decision.DENY, str(exc))
            return GovernanceResult(decision=Decision.DENY, reason=str(exc), audit_seq=seq)

        # 2. Scope (hard block)
        try:
            self._scope.enforce(request.target)
        except ScopeError as exc:
            seq = self._record(principal, request, Decision.DENY, str(exc))
            return GovernanceResult(decision=Decision.DENY, reason=str(exc), audit_seq=seq)

        # 3. Rate budget
        try:
            self._limiter.check(f"{principal.id}:{request.tool}", cost=cost)
        except RateLimitError as exc:
            seq = self._record(principal, request, Decision.DENY, str(exc))
            return GovernanceResult(decision=Decision.DENY, reason=str(exc), audit_seq=seq)

        # 4. Approval gate
        if requires_approval:
            if self._approvals is None:
                reason = "action requires approval but no approval authority is configured"
                seq = self._record(principal, request, Decision.DENY, reason)
                return GovernanceResult(
                    decision=Decision.DENY, reason=reason, audit_seq=seq
                )
            challenge = self._approvals.challenge(
                {
                    "tool": request.tool,
                    "target": request.target,
                    "action": request.action,
                    "engagement_id": principal.engagement_id,
                }
            )
            if not approval_token:
                seq = self._record(
                    principal, request, Decision.NEEDS_APPROVAL, "awaiting signed approval"
                )
                import json

                return GovernanceResult(
                    decision=Decision.NEEDS_APPROVAL,
                    reason="a signed approval token is required for this action",
                    audit_seq=seq,
                    approval_challenge=json.dumps(challenge, sort_keys=True),
                )
            try:
                self._approvals.verify(challenge, approval_token)
            except ApprovalError as exc:
                seq = self._record(principal, request, Decision.DENY, str(exc))
                return GovernanceResult(
                    decision=Decision.DENY, reason=str(exc), audit_seq=seq
                )

        reason = "all governance checks passed"
        seq = self._record(principal, request, Decision.ALLOW, reason)
        return GovernanceResult(decision=Decision.ALLOW, reason=reason, audit_seq=seq)
