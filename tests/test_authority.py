import pytest

from kali_ops_agent.authority import (
    can_override,
    reject_embedded_escalation,
    require_min_tier,
)
from kali_ops_agent.errors import AuthorityError
from kali_ops_agent.models import AuthorityTier, Principal


def _principal(tier: AuthorityTier) -> Principal:
    return Principal(id="op-1", tier=tier, engagement_id="eng-1")


def test_sufficient_tier_passes():
    require_min_tier(_principal(AuthorityTier.DEVELOPER), AuthorityTier.USER)


def test_insufficient_tier_denied():
    with pytest.raises(AuthorityError):
        require_min_tier(_principal(AuthorityTier.USER), AuthorityTier.DEVELOPER)


def test_override_only_downward():
    assert can_override(AuthorityTier.SYSTEM, AuthorityTier.USER)
    assert not can_override(AuthorityTier.USER, AuthorityTier.SYSTEM)
    assert not can_override(AuthorityTier.USER, AuthorityTier.USER)


def test_embedded_cannot_issue_directives():
    with pytest.raises(AuthorityError):
        reject_embedded_escalation(AuthorityTier.EMBEDDED)
    # A real principal tier passes the guard.
    reject_embedded_escalation(AuthorityTier.USER)
