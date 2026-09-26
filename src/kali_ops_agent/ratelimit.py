"""Token-bucket rate limiting, per (principal, tool) pair.

Rate limiting here is a safety budget, not a performance throttle: it bounds how
much a single caller can drive a tool within an engagement window, so a runaway
loop or a compromised caller cannot generate unbounded activity against a target.
"""

from __future__ import annotations

import math
import threading
import time
from dataclasses import dataclass

from .errors import RateLimitError


def _positive_finite(value: float) -> bool:
    """A usable rate/cost is a real, finite, strictly-positive number.

    NaN and infinity must be rejected explicitly: ``nan <= 0`` is False, so a
    naive positivity check lets a non-finite value through, and a NaN capacity
    makes ``tokens < cost`` always False — silently disabling the safety budget.
    """
    return math.isfinite(value) and value > 0


@dataclass
class BucketConfig:
    """Capacity is the burst ceiling; refill_per_sec the sustained rate."""

    capacity: float = 10.0
    refill_per_sec: float = 1.0

    def __post_init__(self) -> None:
        if not _positive_finite(self.capacity) or not _positive_finite(self.refill_per_sec):
            raise ValueError("capacity and refill_per_sec must be positive and finite")


class _Bucket:
    __slots__ = ("tokens", "updated")

    def __init__(self, tokens: float, updated: float) -> None:
        self.tokens = tokens
        self.updated = updated


class TokenBucketLimiter:
    """Thread-safe token-bucket limiter keyed by an arbitrary string."""

    def __init__(self, config: BucketConfig | None = None, *, clock=time.monotonic) -> None:
        self._config = config or BucketConfig()
        self._clock = clock
        self._buckets: dict[str, _Bucket] = {}
        self._lock = threading.Lock()

    def _refill(self, bucket: _Bucket, now: float) -> None:
        elapsed = max(0.0, now - bucket.updated)
        bucket.tokens = min(
            self._config.capacity,
            bucket.tokens + elapsed * self._config.refill_per_sec,
        )
        bucket.updated = now

    def check(self, key: str, cost: float = 1.0) -> None:
        """Consume ``cost`` tokens for ``key`` or fail closed.

        Raises:
            RateLimitError: if insufficient budget remains.
        """
        if not _positive_finite(cost):
            raise ValueError("cost must be positive and finite")
        now = self._clock()
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = _Bucket(self._config.capacity, now)
                self._buckets[key] = bucket
            self._refill(bucket, now)
            if bucket.tokens < cost:
                raise RateLimitError(
                    f"rate budget exhausted for '{key}': "
                    f"{bucket.tokens:.2f} tokens available, {cost:.2f} required"
                )
            bucket.tokens -= cost

    def available(self, key: str) -> float:
        now = self._clock()
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                return self._config.capacity
            self._refill(bucket, now)
            return bucket.tokens
