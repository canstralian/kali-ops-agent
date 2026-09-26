"""Authority hierarchy enforcement.

Precedence is System > Developer > User > Embedded. The one rule that matters:
a directive from a lower tier can never override or widen a constraint set by a
higher tier. In practice the most important boundary is EMBEDDED — instructions
that arrive *inside* tool output or fetched web content carry the lowest
authority and must never be able to expand scope, grant approvals, or raise the
caller's own tier.
"""

from __future__ import annotations

from .errors import AuthorityError
from .models import AuthorityTier, Principal


def require_min_tier(principal: Principal, minimum: AuthorityTier) -> None:
    """Fail closed unless ``principal`` acts at or above ``minimum``.

    Raises:
        AuthorityError: if the principal's tier is below the requirement.
    """
    if principal.tier < minimum:
        raise AuthorityError(
            f"action requires {minimum.name} authority; "
            f"principal '{principal.id}' holds {principal.tier.name}"
        )


def can_override(directive_tier: AuthorityTier, constraint_tier: AuthorityTier) -> bool:
    """Return whether a directive may override a constraint set at another tier.

    A directive overrides only constraints set at a strictly lower tier. Equal
    tiers do not override (last-writer-wins is a policy decision the caller must
    make explicitly, not a silent default), and lower never overrides higher.
    """
    return directive_tier > constraint_tier


def reject_embedded_escalation(directive_tier: AuthorityTier) -> None:
    """Guard used at trust boundaries where content of unknown origin is parsed.

    Anything flowing in from tool output or fetched documents is treated as
    EMBEDDED. Such content may inform, never command: if it attempts an action
    reserved for a higher tier, deny.

    Raises:
        AuthorityError: if the directive originates at the EMBEDDED tier.
    """
    if directive_tier <= AuthorityTier.EMBEDDED:
        raise AuthorityError(
            "embedded content cannot issue governed directives; treated as data"
        )
