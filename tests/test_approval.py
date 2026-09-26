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
