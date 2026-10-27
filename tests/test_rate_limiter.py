import asyncio
import pytest
from sentinel_webhook.rate_limiter import RateLimitExceededError, TokenBucketRateLimiter


def test_token_bucket_burst_and_exhaustion():
    async def run():
        # Rate: 1 token/sec, Burst Capacity: 3 tokens
        limiter = TokenBucketRateLimiter(rate_per_second=1.0, burst_capacity=3.0)
        tenant = "tenant_alpha"

        # Consume 3 tokens from burst
        allowed, retry_after, remaining = await limiter.acquire(tenant, cost=1.0, current_time=100.0)
        assert allowed is True
        assert remaining == 2

        allowed, retry_after, remaining = await limiter.acquire(tenant, cost=1.0, current_time=100.0)
        assert allowed is True
        assert remaining == 1

        allowed, retry_after, remaining = await limiter.acquire(tenant, cost=1.0, current_time=100.0)
        assert allowed is True
        assert remaining == 0

        # 4th token in same second should be rate-limited
        with pytest.raises(RateLimitExceededError) as exc_info:
            await limiter.acquire(tenant, cost=1.0, current_time=100.0)

        assert exc_info.value.retry_after == pytest.approx(1.0, rel=0.01)

        # After 1.5 seconds, 1.5 tokens replenished, consuming 1 token should succeed
        allowed, retry_after, remaining = await limiter.acquire(tenant, cost=1.0, current_time=101.5)
        assert allowed is True
        assert remaining == 0

    asyncio.run(run())


def test_multi_tenant_isolation():
    async def run():
        limiter = TokenBucketRateLimiter(rate_per_second=1.0, burst_capacity=2.0)

        # Exhaust tenant 1
        await limiter.acquire("tenant_1", cost=2.0, current_time=50.0)

        with pytest.raises(RateLimitExceededError):
            await limiter.acquire("tenant_1", cost=1.0, current_time=50.0)

        # Tenant 2 is unaffected and has full burst capacity
        allowed, _, remaining = await limiter.acquire("tenant_2", cost=2.0, current_time=50.0)
        assert allowed is True
        assert remaining == 0

    asyncio.run(run())
