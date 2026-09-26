import pytest

from kali_ops_agent.errors import RateLimitError
from kali_ops_agent.ratelimit import BucketConfig, TokenBucketLimiter


class FakeClock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t

    def advance(self, dt):
        self.t += dt


def test_budget_exhausts_then_refills():
    clock = FakeClock()
    limiter = TokenBucketLimiter(
        BucketConfig(capacity=2, refill_per_sec=1), clock=clock
    )
    limiter.check("op:tool")
    limiter.check("op:tool")
    with pytest.raises(RateLimitError):
        limiter.check("op:tool")
    clock.advance(1.0)
    limiter.check("op:tool")  # one token refilled


def test_keys_are_independent():
    limiter = TokenBucketLimiter(BucketConfig(capacity=1, refill_per_sec=1))
    limiter.check("a:tool")
    limiter.check("b:tool")  # different key, own budget


def test_invalid_config_rejected():
    with pytest.raises(ValueError):
        BucketConfig(capacity=0, refill_per_sec=1)
