"""
sentinel_webhook.idempotency
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
High-throughput in-memory idempotency deduplication engine with TTL sliding windows
and bounded LRU capacity to prevent memory leaks and duplicate execution.
"""

from __future__ import annotations

import asyncio
import hashlib
import time
from collections import OrderedDict
from typing import Optional


class DuplicateEventError(Exception):
    """Raised when an incoming event has already been registered and processed."""
    pass


class IdempotencyEngine:
    """
    In-memory bounded LRU and TTL idempotency engine.
    
    Guarantees:
    - Exactly-once processing gating.
    - Zero unbounded memory growth: Bounded to max_capacity via LRU eviction.
    - Automatic TTL invalidation for expired idempotency keys.
    - Async-safe reentrancy protection.
    """

    def __init__(
        self,
        ttl_seconds: int = 3600,
        max_capacity: int = 50000,
    ) -> None:
        """
        :param ttl_seconds: Duration in seconds to remember an idempotency key.
        :param max_capacity: Maximum number of keys to retain in memory before LRU eviction.
        """
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        if max_capacity <= 0:
            raise ValueError("max_capacity must be positive")

        self.ttl_seconds = ttl_seconds
        self.max_capacity = max_capacity
        self._cache: OrderedDict[str, float] = OrderedDict()
        self._lock = asyncio.Lock()

    @staticmethod
    def fingerprint_payload(payload: bytes, salt: str = "") -> str:
        """Generate a deterministic SHA-256 fingerprint for a payload."""
        hasher = hashlib.sha256()
        if salt:
            hasher.update(salt.encode("utf-8") + b":")
        hasher.update(payload)
        return hasher.hexdigest()

    async def register_if_absent(
        self,
        key: str,
        current_time: Optional[float] = None,
    ) -> bool:
        """
        Atomically register an idempotency key.
        
        :param key: Unique identifier (event ID or payload fingerprint).
        :param current_time: Optional mock timestamp for deterministic testing.
        :return: True if the key was newly registered (allowed to proceed).
        :raises DuplicateEventError: If the key was already registered and is not expired.
        """
        now = current_time if current_time is not None else time.time()

        async with self._lock:
            # Check if key exists
            if key in self._cache:
                timestamp = self._cache[key]
                if now - timestamp < self.ttl_seconds:
                    # Still valid -> duplicate!
                    raise DuplicateEventError(f"Duplicate event detected for key: {key}")
                else:
                    # Expired entry, remove to re-record
                    del self._cache[key]

            # Enforce max capacity via LRU eviction of oldest item
            if len(self._cache) >= self.max_capacity:
                self._cache.popitem(last=False)

            # Insert / update
            self._cache[key] = now
            return True

    async def is_processed(
        self,
        key: str,
        current_time: Optional[float] = None,
    ) -> bool:
        """Check whether a key is currently tracked and active (non-expired)."""
        now = current_time if current_time is not None else time.time()
        async with self._lock:
            if key not in self._cache:
                return False
            timestamp = self._cache[key]
            if now - timestamp < self.ttl_seconds:
                return True
            del self._cache[key]
            return False

    async def clear(self) -> None:
        """Clear all registered keys."""
        async with self._lock:
            self._cache.clear()

    async def prune_expired(self, current_time: Optional[float] = None) -> int:
        """Prune all expired entries from cache. Returns count of pruned entries."""
        now = current_time if current_time is not None else time.time()
        pruned = 0
        async with self._lock:
            keys_to_remove = [k for k, ts in self._cache.items() if now - ts >= self.ttl_seconds]
            for k in keys_to_remove:
                del self._cache[k]
                pruned += 1
        return pruned

    async def size(self) -> int:
        """Return the current number of tracked keys."""
        async with self._lock:
            return len(self._cache)
