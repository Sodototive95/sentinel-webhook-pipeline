import asyncio
import pytest
from sentinel_webhook.idempotency import IdempotencyEngine
from sentinel_webhook.pipeline import IngestionEvent, IngestionPipeline
from sentinel_webhook.rate_limiter import TokenBucketRateLimiter
from sentinel_webhook.signature import SignatureVerifier


def test_end_to_end_pipeline_flow():
    async def run():
        secret = "pipeline_test_secret_key"
        verifier = SignatureVerifier(secret)
        idempotency = IdempotencyEngine(ttl_seconds=60)
        rate_limiter = TokenBucketRateLimiter(rate_per_second=100.0, burst_capacity=100.0)

        pipeline = IngestionPipeline(
            verifier=verifier,
            idempotency=idempotency,
            rate_limiter=rate_limiter,
            max_queue_size=50,
            worker_count=2,
        )

        processed_events = []

        async def mock_handler(event: IngestionEvent):
            await asyncio.sleep(0.01)
            processed_events.append(event.event_id)

        await pipeline.start(mock_handler)

        payload = b'{"status":"paid"}'
        sig = verifier.compute_hmac(payload)
        headers = {"x-signature-sha256": sig}

        # Submit valid event
        res1 = await pipeline.submit("evt_1", "tenant_a", payload, headers)
        assert res1.status == "accepted"

        # Submit duplicate event -> rejected by idempotency
        res_dup = await pipeline.submit("evt_1", "tenant_a", payload, headers)
        assert res_dup.status == "duplicate"

        # Submit event with bad signature -> rejected by signature verifier
        bad_headers = {"x-signature-sha256": "bad_signature"}
        res_bad = await pipeline.submit("evt_2", "tenant_a", payload, bad_headers)
        assert res_bad.status == "invalid_signature"

        # Graceful shutdown with drain
        await pipeline.shutdown(drain=True, timeout=2.0)

        assert "evt_1" in processed_events
        assert pipeline.processed_count == 1
        assert not pipeline.is_running

    asyncio.run(run())
