import asyncio
import pytest
from sentinel_webhook.idempotency import DuplicateEventError, IdempotencyEngine


def test_idempotency_registration_and_duplicate_rejection():
    async def run():
        engine = IdempotencyEngine(ttl_seconds=10, max_capacity=100)

        # First attempt: succeeds
        assert await engine.register_if_absent("evt_1001", current_time=1000.0) is True

        # Duplicate attempt: raises DuplicateEventError
        with pytest.raises(DuplicateEventError):
            await engine.register_if_absent("evt_1001", current_time=1005.0)

        # After TTL: succeeds again
        assert await engine.register_if_absent("evt_1001", current_time=1015.0) is True

    asyncio.run(run())


def test_idempotency_lru_capacity_eviction():
    async def run():
        # Capacity = 3
        engine = IdempotencyEngine(ttl_seconds=100, max_capacity=3)

        await engine.register_if_absent("k1", current_time=10.0)
        await engine.register_if_absent("k2", current_time=20.0)
        await engine.register_if_absent("k3", current_time=30.0)

        assert await engine.size() == 3

        # Adding 4th item evicts k1 (oldest)
        await engine.register_if_absent("k4", current_time=40.0)
        assert await engine.size() == 3

        assert await engine.is_processed("k1", current_time=45.0) is False
        assert await engine.is_processed("k2", current_time=45.0) is True
        assert await engine.is_processed("k3", current_time=45.0) is True
        assert await engine.is_processed("k4", current_time=45.0) is True

    asyncio.run(run())


def test_payload_fingerprinting():
    p1 = b'{"amount": 100}'
    p2 = b'{"amount": 100}'
    p3 = b'{"amount": 200}'

    h1 = IdempotencyEngine.fingerprint_payload(p1)
    h2 = IdempotencyEngine.fingerprint_payload(p2)
    h3 = IdempotencyEngine.fingerprint_payload(p3)

    assert h1 == h2
    assert h1 != h3
