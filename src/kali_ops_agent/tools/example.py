"""Reference tool adapter — the template every real adapter follows.

``ReconStub`` performs no network activity of its own. It exists to demonstrate,
end to end, the one contract that matters: a tool asks the governance engine for
a verdict *before* it would act, and does nothing on a denial. Wiring a real
Kali tool means replacing the ``_perform`` body with the actual, authorized
invocation — the surrounding governance flow stays exactly as it is.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from ..engine import GovernanceEngine
from ..models import AuthorityTier, Decision, GovernanceResult, Principal, ToolRequest


class GovernedTool(ABC):
    """Base class binding a tool to the governance engine.

    Subclasses declare their authority/approval requirements and implement
    ``_perform``, which is only ever reached after ``Decision.ALLOW``.
    """

    name: str = "governed-tool"
    min_tier: AuthorityTier = AuthorityTier.USER
    requires_approval: bool = False

    def __init__(self, engine: GovernanceEngine) -> None:
        self._engine = engine

    @abstractmethod
    def _perform(self, request: ToolRequest) -> dict[str, object]:
        """Do the real work. Reached only on an allowed request."""

    def run(
        self,
        principal: Principal,
        target: str,
        *,
        action: str = "default",
        arguments: dict[str, str] | None = None,
        approval_token: str | None = None,
    ) -> dict[str, object]:
        request = ToolRequest(
            tool=self.name,
            target=target,
            action=action,
            arguments=arguments or {},
        )
        verdict: GovernanceResult = self._engine.evaluate(
            principal,
            request,
            min_tier=self.min_tier,
            requires_approval=self.requires_approval,
            approval_token=approval_token,
        )
        if verdict.decision is not Decision.ALLOW:
            return {
                "ok": False,
                "decision": verdict.decision.value,
                "reason": verdict.reason,
                "approval_challenge": verdict.approval_challenge,
                "audit_seq": verdict.audit_seq,
            }
        result = self._perform(request)
        return {
            "ok": True,
            "decision": verdict.decision.value,
            "audit_seq": verdict.audit_seq,
            "result": result,
        }


class ReconStub(GovernedTool):
    """A benign, no-op reconnaissance template.

    Returns a structured description of the action that *would* run against the
    (already scope-validated) target. It deliberately performs no I/O, so the
    scaffold is safe to run anywhere while still exercising the full governance
    path.
    """

    name = "recon-stub"
    min_tier = AuthorityTier.USER
    requires_approval = False

    def _perform(self, request: ToolRequest) -> dict[str, object]:
        return {
            "tool": self.name,
            "target": request.target,
            "action": request.action,
            "note": "governance passed; replace _perform with an authorized invocation",
        }
