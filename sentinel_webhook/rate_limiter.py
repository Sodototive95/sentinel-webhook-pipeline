"""
sentinel_webhook.rate_limiter
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
High-performance asynchronous Token Bucket rate limiter with per-tenant tracking,
configurable burst limits, and RFC 6585 compliant retry headers.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Dict, Optional, Tuple


class RateLimitExceededError(Exception):
    """Raised when request rate exceeds allowed capacity."""

    def __init__(self, message: str, retry_after: float, remaining: int) -> None:
        super().__init__(message)
        self.retry_after = retry_after
        self.remaining = remaining


@dataclass
class BucketState:
    tokens: float
    last_updated: float


class TokenBucketRateLimiter:
    """
    Asynchronous per-tenant Token Bucket rate limiter.
    
    Features:
    - Independent bucket per client/tenant key.
    - Continuous fractional token replenishment.
    - Bounded maximum burst capacity.
    - Calculates precise `Retry-After` seconds and `X-RateLimit-Remaining`.
    """

    def __init__(
        self,
        rate_per_second: float = 100.0,
        burst_capacity: float = 200.0,
        cleanup_interval_seconds: float = 600.0,
    ) -> None:
        """
        :param rate_per_second: Token replenishment rate per second.
        :param burst_capacity: Maximum tokens a bucket can hold.
        :param cleanup_interval_seconds: Retention time for idle client buckets.
        """
        if rate_per_second <= 0:
            raise ValueError("rate_per_second must be positive")
        if burst_capacity <= 0:
            raise ValueError("burst_capacity must be positive")

        self.rate = float(rate_per_second)
        self.capacity = float(burst_capacity)
        self.cleanup_interval = float(cleanup_interval_seconds)
        self._buckets: Dict[str, BucketState] = {}
        self._lock = asyncio.Lock()

    async def acquire(
        self,
        key: str,
        cost: float = 1.0,
        current_time: Optional[float] = None,
    ) -> Tuple[bool, float, int]:
        """
        Attempt to consume `cost` tokens for tenant `key`.
        
        :param key: Tenant identifier (e.g., API key, client IP, source tenant).
        :param cost: Number of tokens requested (default 1.0).
        :param current_time: Optional mock timestamp for deterministic testing.
        :return: (allowed: bool, retry_after: float, remaining: int)
        :raises RateLimitExceededError: If insufficient tokens are available.
        """
        now = current_time if current_time is not None else time.time()

        async with self._lock:
            state = self._buckets.get(key)
            if state is None:
                # Brand new bucket: starts full
                state = BucketState(tokens=self.capacity, last_updated=now)
                self._buckets[key] = state
            else:
                # Replenish tokens based on elapsed time
                elapsed = max(0.0, now - state.last_updated)
                replenished = elapsed * self.rate
                state.tokens = min(self.capacity, state.tokens + replenished)
                state.last_updated = now

            if state.tokens >= cost:
                state.tokens -= cost
                remaining = int(state.tokens)
                return True, 0.0, remaining

            # Not enough tokens
            deficit = cost - state.tokens
            retry_after = deficit / self.rate
            remaining = int(state.tokens)

            raise RateLimitExceededError(
                message=f"Rate limit exceeded for key '{key}'. Retry in {retry_after:.2f}s",
                retry_after=retry_after,
                remaining=remaining,
            )

    async def prune_idle_buckets(self, current_time: Optional[float] = None) -> int:
        """Remove buckets that have been idle longer than cleanup_interval."""
        now = current_time if current_time is not None else time.time()
        pruned = 0
        async with self._lock:
            idle_keys = [
                k for k, state in self._buckets.items()
                if (now - state.last_updated) > self.cleanup_interval and state.tokens >= self.capacity
            ]
            for k in idle_keys:
                del self._buckets[k]
                pruned += 1
        return pruned

    async def bucket_count(self) -> int:
        """Return total active buckets."""
        async with self._lock:
            return len(self._buckets)
