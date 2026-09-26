import pytest

from kali_ops_agent.approval import ApprovalAuthority, ApprovalConfig
from kali_ops_agent.errors import ApprovalError


class FakeClock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t

    def advance(self, dt):
        self.t += dt


def test_valid_token_verifies():
    auth = ApprovalAuthority(b"secret")
    challenge = auth.challenge({"tool": "recon-stub", "target": "app.example.com"})
    token = auth.sign(challenge)
    auth.verify(challenge, token)  # no raise


def test_forged_token_rejected():
    auth = ApprovalAuthority(b"secret")
    challenge = auth.challenge({"tool": "recon-stub", "target": "app.example.com"})
    with pytest.raises(ApprovalError):
        auth.verify(challenge, "deadbeef")


def test_token_from_other_secret_rejected():
    challenge = ApprovalAuthority(b"secret-a").challenge({"tool": "t", "target": "x"})
    token = ApprovalAuthority(b"secret-b").sign(challenge)
    with pytest.raises(ApprovalError):
        ApprovalAuthority(b"secret-a").verify(challenge, token)


def test_expired_token_rejected():
    clock = FakeClock()
    auth = ApprovalAuthority(b"secret", ApprovalConfig(ttl_seconds=60), clock=clock)
    challenge = auth.challenge({"tool": "t", "target": "x"})
    token = auth.sign(challenge)
    clock.advance(61)
    with pytest.raises(ApprovalError):
        auth.verify(challenge, token)


def test_empty_secret_rejected():
    with pytest.raises(ValueError):
        ApprovalAuthority(b"")


def test_verify_is_side_effect_free():
    # verify() validates but does not consume, so it may be called repeatedly.
    auth = ApprovalAuthority(b"secret")
    challenge = auth.challenge({"tool": "recon-stub", "target": "app.example.com"})
    token = auth.sign(challenge)
    auth.verify(challenge, token)
    auth.verify(challenge, token)  # still valid — consumption happens in consume()


def test_consume_is_single_use():
    auth = ApprovalAuthority(b"secret")
    challenge = auth.challenge({"tool": "recon-stub", "target": "app.example.com"})
    auth.consume(challenge)  # first spend succeeds
    with pytest.raises(ApprovalError):
        auth.consume(challenge)  # replay within TTL is rejected


def test_missing_nonce_rejected():
    auth = ApprovalAuthority(b"secret")
    challenge = auth.challenge({"tool": "t", "target": "x"})
    del challenge["nonce"]
    token = auth.sign(challenge)  # signs the (nonce-less) challenge, so sig matches
    with pytest.raises(ApprovalError):
        auth.verify(challenge, token)


def test_token_cannot_be_replayed_at_the_expiry_boundary():
    clock = FakeClock()
    auth = ApprovalAuthority(b"secret", ApprovalConfig(ttl_seconds=60), clock=clock)
    challenge = auth.challenge({"tool": "t", "target": "x"})
    clock.t = challenge["expires_at"]  # exactly at expiry: still acceptable once
    auth.consume(challenge)
    with pytest.raises(ApprovalError):
        auth.consume(challenge)  # the nonce must not be purged at this instant
