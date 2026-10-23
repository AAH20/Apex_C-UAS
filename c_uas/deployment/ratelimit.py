"""
Token-bucket rate limiter, per client.

Deterministic by design: the clock is injectable so tests can simulate the
passage of time without sleeping, and the same inputs always yield the same
allow/deny decision. Clients are identified by their API key.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Callable, Optional


@dataclass
class TokenBucket:
    """A token bucket with a fixed refill rate and a burst capacity."""

    rate: float
    burst: int
    _tokens: float = field(init=False)
    _last: float = field(init=False)

    def __post_init__(self) -> None:
        self._tokens = float(self.burst)
        self._last = _now()

    def consume(self, now: Optional[float] = None) -> bool:
        """Return True if a token was consumed, False if the bucket is empty."""
        if now is None:
            now = _now()
        elapsed = max(0.0, now - self._last)
        self._last = now
        self._tokens = min(float(self.burst), self._tokens + elapsed * self.rate)
        if self._tokens >= 1.0:
            self._tokens -= 1.0
            return True
        return False


def _now() -> float:
    import time

    return time.monotonic()


class RateLimiter:
    """Per-client token-bucket rate limiter keyed by client id (API key)."""

    def __init__(
        self,
        rate: float,
        burst: int,
        clock: Callable[[], float] = _now,
    ) -> None:
        self.rate = rate
        self.burst = burst
        self._clock = clock
        self._buckets: dict = {}
        self._lock = threading.RLock()

    def bucket_for(self, client_id: str) -> TokenBucket:
        with self._lock:
            bucket = self._buckets.get(client_id)
            if bucket is None:
                bucket = TokenBucket(rate=self.rate, burst=self.burst)
                self._buckets[client_id] = bucket
            return bucket

    def allow(self, client_id: str) -> bool:
        """Return True if the request from client_id is permitted."""
        return self.bucket_for(client_id).consume(now=self._clock())
