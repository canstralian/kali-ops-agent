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


class _AdvancingClock:
    """Clock that advances one second on every read, to prove tokens survive
    a clock tick between the challenge call and the token-bearing call."""

    def __init__(self, start=1000.0):
        self.t = start

    def __call__(self):
        now = self.t
        self.t += 1.0
        return now


def test_needs_approval_then_allow_with_token_across_a_clock_tick():
    approvals = ApprovalAuthority(b"secret", clock=_AdvancingClock())
    engine = _engine(approvals=approvals)

    pending = engine.evaluate(_principal(), _request(), requires_approval=True)
    assert pending.decision is Decision.NEEDS_APPROVAL
    challenge_json = pending.approval_challenge
    token = approvals.sign(json.loads(challenge_json))

    # The token-bearing call happens after the clock has advanced; the signed
    # challenge is echoed back verbatim, so it must still verify.
    approved = engine.evaluate(
        _principal(),
        _request(),
        requires_approval=True,
        approval_token=token,
        approval_challenge=challenge_json,
    )
    assert approved.decision is Decision.ALLOW


def test_approval_token_not_bound_to_a_different_target_is_denied():
    approvals = ApprovalAuthority(b"secret")
    engine = _engine(scope=("app.example.com", "api.example.com"), approvals=approvals)

    pending = engine.evaluate(
        _principal(), _request(target="app.example.com"), requires_approval=True
    )
    token = approvals.sign(json.loads(pending.approval_challenge))

    # Same signed challenge, but replayed against a different in-scope target.
    replayed = engine.evaluate(
        _principal(),
        _request(target="api.example.com"),
        requires_approval=True,
        approval_token=token,
        approval_challenge=pending.approval_challenge,
    )
    assert replayed.decision is Decision.DENY


def test_approval_token_not_bound_to_tampered_arguments_is_denied():
    approvals = ApprovalAuthority(b"secret")
    engine = _engine(approvals=approvals)

    benign = ToolRequest(tool="recon-stub", target="app.example.com", arguments={"n": "1"})
    pending = engine.evaluate(_principal(), benign, requires_approval=True)
    token = approvals.sign(json.loads(pending.approval_challenge))

    # Same signed challenge/token, but a different arguments payload.
    tampered = ToolRequest(
        tool="recon-stub", target="app.example.com", arguments={"n": "1", "cmd": "evil"}
    )
    replayed = engine.evaluate(
        _principal(),
        tampered,
        requires_approval=True,
        approval_token=token,
        approval_challenge=pending.approval_challenge,
    )
    assert replayed.decision is Decision.DENY

    # The originally-signed arguments still verify.
    approved = engine.evaluate(
        _principal(),
        ToolRequest(tool="recon-stub", target="app.example.com", arguments={"n": "1"}),
        requires_approval=True,
        approval_token=token,
        approval_challenge=pending.approval_challenge,
    )
    assert approved.decision is Decision.ALLOW


def test_rate_denied_request_does_not_spend_the_approval_token():
    approvals = ApprovalAuthority(b"secret")
    clock = {"t": 0.0}
    limiter = TokenBucketLimiter(
        BucketConfig(capacity=1, refill_per_sec=1), clock=lambda: clock["t"]
    )
    engine = GovernanceEngine(
        scope=ScopeGuard(["app.example.com"]),
        limiter=limiter,
        audit=AuditLog(),
        approvals=approvals,
    )
    principal, request = _principal(), _request()

    engine.evaluate(principal, request)  # drain the single rate token
    pending = engine.evaluate(principal, request, requires_approval=True)
    token = approvals.sign(json.loads(pending.approval_challenge))
    challenge = pending.approval_challenge

    denied = engine.evaluate(
        principal,
        request,
        requires_approval=True,
        approval_token=token,
        approval_challenge=challenge,
    )
    assert denied.decision is Decision.DENY  # rate-limited, token NOT spent

    clock["t"] = 5.0  # budget refills
    allowed = engine.evaluate(
        principal,
        request,
        requires_approval=True,
        approval_token=token,
        approval_challenge=challenge,
    )
    assert allowed.decision is Decision.ALLOW  # same token still works


def test_needs_approval_does_not_consume_rate_budget():
    approvals = ApprovalAuthority(b"secret")
    engine = _engine(approvals=approvals, capacity=1)

    # Two NEEDS_APPROVAL round-trips must not exhaust a capacity-1 bucket...
    engine.evaluate(_principal(), _request(), requires_approval=True)
    engine.evaluate(_principal(), _request(), requires_approval=True)

    # ...so a single approved action still has budget to spend exactly once.
    pending = engine.evaluate(_principal(), _request(), requires_approval=True)
    token = approvals.sign(json.loads(pending.approval_challenge))
    approved = engine.evaluate(
        _principal(),
        _request(),
        requires_approval=True,
        approval_token=token,
        approval_challenge=pending.approval_challenge,
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
