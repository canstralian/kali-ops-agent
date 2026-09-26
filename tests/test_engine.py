import json

from kali_ops_agent.approval import ApprovalAuthority
from kali_ops_agent.audit import AuditLog
from kali_ops_agent.engine import GovernanceEngine
from kali_ops_agent.models import AuthorityTier, Decision, Principal, ToolRequest
from kali_ops_agent.ratelimit import BucketConfig, TokenBucketLimiter
from kali_ops_agent.scope import ScopeGuard


def _engine(scope=("app.example.com",), approvals=None, capacity=5):
    return GovernanceEngine(
        scope=ScopeGuard(list(scope)),
        limiter=TokenBucketLimiter(BucketConfig(capacity=capacity, refill_per_sec=1)),
        audit=AuditLog(),
        approvals=approvals,
    )


def _principal(tier=AuthorityTier.USER):
    return Principal(id="op-1", tier=tier, engagement_id="eng-1")


def _request(target="app.example.com"):
    return ToolRequest(tool="recon-stub", target=target)


def test_allow_when_all_checks_pass():
    engine = _engine()
    result = engine.evaluate(_principal(), _request())
    assert result.decision is Decision.ALLOW
    assert result.audit_seq == 0


def test_out_of_scope_denied_and_audited():
    engine = _engine()
    result = engine.evaluate(_principal(), _request(target="evil.example.net"))
    assert result.decision is Decision.DENY
    assert "not within the authorized" in result.reason


def test_low_authority_denied():
    engine = _engine()
    result = engine.evaluate(
        _principal(AuthorityTier.EMBEDDED), _request(), min_tier=AuthorityTier.USER
    )
    assert result.decision is Decision.DENY


def test_needs_approval_then_allow_with_token():
    approvals = ApprovalAuthority(b"secret")
    engine = _engine(approvals=approvals)

    pending = engine.evaluate(_principal(), _request(), requires_approval=True)
    assert pending.decision is Decision.NEEDS_APPROVAL
    challenge = json.loads(pending.approval_challenge)
    token = approvals.sign(challenge)

    approved = engine.evaluate(
        _principal(), _request(), requires_approval=True, approval_token=token
    )
    assert approved.decision is Decision.ALLOW


def test_approval_required_without_authority_configured_denies():
    engine = _engine(approvals=None)
    result = engine.evaluate(_principal(), _request(), requires_approval=True)
    assert result.decision is Decision.DENY


def test_every_decision_is_recorded():
    engine = _engine()
    engine.evaluate(_principal(), _request())
    engine.evaluate(_principal(), _request(target="evil.example.net"))
    assert len(engine._audit.entries) == 2
    engine._audit.verify()
