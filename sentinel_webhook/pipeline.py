"""
sentinel_webhook.pipeline
~~~~~~~~~~~~~~~~~~~~~~~~~
Asynchronous webhook ingestion pipeline orchestrating signature verification,
idempotency deduplication, rate limiting, and backpressure-governed worker queues.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, Optional

from .idempotency import DuplicateEventError, IdempotencyEngine
from .rate_limiter import RateLimitExceededError, TokenBucketRateLimiter
from .signature import SignatureVerificationError, SignatureVerifier

logger = logging.getLogger("sentinel_webhook.pipeline")


class PipelineOverloadedError(Exception):
    """Raised when the internal worker queue is full (backpressure applied)."""
    pass


class PipelineClosedError(Exception):
    """Raised when attempting to submit events to a pipeline that is shutting down."""
    pass


@dataclass
class IngestionEvent:
    event_id: str
    tenant_id: str
    payload: bytes
    headers: Dict[str, str]
    created_at: float
    metadata: Dict[str, Any]


@dataclass
class IngestionResult:
    status: str  # "accepted", "duplicate", "rate_limited", "invalid_signature", "overloaded"
    event_id: str
    message: str
    retry_after: float = 0.0


HandlerFunc = Callable[[IngestionEvent], Awaitable[None]]


class IngestionPipeline:
    """
    High-throughput asynchronous webhook and stream ingestion pipeline.
    
    Architecture:
    1. Fast-Path Gating:
       - Signature validation (HMAC SHA-256).
       - Rate limiting (Token Bucket).
       - Idempotency check (TTL LRU cache).
    2. Backpressure Buffer:
       - Bounded `asyncio.Queue` with high-watermark rejection.
    3. Asynchronous Worker Pool:
       - Concurrent consumer coroutines executing downstream event handlers.
    4. Graceful Drain:
       - Supports clean draining on SIGINT/SIGTERM without event loss.
    """

    def __init__(
        self,
        verifier: Optional[SignatureVerifier] = None,
        idempotency: Optional[IdempotencyEngine] = None,
        rate_limiter: Optional[TokenBucketRateLimiter] = None,
        max_queue_size: int = 10000,
        worker_count: int = 4,
    ) -> None:
        self.verifier = verifier
        self.idempotency = idempotency or IdempotencyEngine()
        self.rate_limiter = rate_limiter or TokenBucketRateLimiter()
        self.max_queue_size = max_queue_size
        self.worker_count = worker_count

        self._queue: asyncio.Queue[IngestionEvent] = asyncio.Queue(maxsize=max_queue_size)
        self._workers: list[asyncio.Task[None]] = []
        self._running = False
        self._draining = False
        self._processed_count = 0
        self._error_count = 0

    @property
    def queue_size(self) -> int:
        return self._queue.qsize()

    @property
    def processed_count(self) -> int:
        return self._processed_count

    @property
    def is_running(self) -> bool:
        return self._running

    async def start(self, handler: HandlerFunc) -> None:
        """Start the background worker pool."""
        if self._running:
            return

        self._running = True
        self._draining = False
        self._workers = [
            asyncio.create_task(self._worker_loop(i, handler), name=f"sentinel-worker-{i}")
            for i in range(self.worker_count)
        ]
        logger.info(f"IngestionPipeline started with {self.worker_count} workers.")

    async def _worker_loop(self, worker_id: int, handler: HandlerFunc) -> None:
        """Internal worker consumer loop."""
        while self._running or (self._draining and not self._queue.empty()):
            try:
                try:
                    event = await asyncio.wait_for(self._queue.get(), timeout=0.2)
                except asyncio.TimeoutError:
                    if self._draining and self._queue.empty():
                        break
                    continue

                try:
                    await handler(event)
                    self._processed_count += 1
                except Exception as e:
                    self._error_count += 1
                    logger.error(f"Worker {worker_id} error processing event {event.event_id}: {e}")
                finally:
                    self._queue.task_done()
            except asyncio.CancelledError:
                break

    async def submit(
        self,
        event_id: str,
        tenant_id: str,
        payload: bytes,
        headers: Dict[str, str],
        signature_format: str = "raw",  # "raw", "github", "stripe", "none"
        metadata: Optional[Dict[str, Any]] = None,
    ) -> IngestionResult:
        """
        Process and enqueue an incoming webhook or event.
        
        Performs fast-path validation before enqueueing.
        """
        if not self._running or self._draining:
            raise PipelineClosedError("Pipeline is not accepting events (closed or draining)")

        # 1. Signature Verification Gate
        if self.verifier and signature_format != "none":
            try:
                if signature_format == "github":
                    sig = headers.get("x-hub-signature-256", headers.get("X-Hub-Signature-256", ""))
                    self.verifier.verify_github(payload, sig)
                elif signature_format == "stripe":
                    sig = headers.get("stripe-signature", headers.get("Stripe-Signature", ""))
                    self.verifier.verify_stripe(payload, sig)
                elif signature_format == "raw":
                    sig = headers.get("x-signature-sha256", headers.get("X-Signature-SHA256", ""))
                    self.verifier.verify_raw(payload, sig)
            except SignatureVerificationError as e:
                return IngestionResult(
                    status="invalid_signature",
                    event_id=event_id,
                    message=f"Signature verification failed: {e}",
                )

        # 2. Rate Limiting Gate
        if self.rate_limiter:
            try:
                await self.rate_limiter.acquire(tenant_id)
            except RateLimitExceededError as e:
                return IngestionResult(
                    status="rate_limited",
                    event_id=event_id,
                    message=str(e),
                    retry_after=e.retry_after,
                )

        # 3. Idempotency Gate
        if self.idempotency:
            try:
                await self.idempotency.register_if_absent(event_id)
            except DuplicateEventError as e:
                return IngestionResult(
                    status="duplicate",
                    event_id=event_id,
                    message=str(e),
                )

        # 4. Backpressure & Queue Insertion
        if self._queue.full():
            return IngestionResult(
                status="overloaded",
                event_id=event_id,
                message="Pipeline queue is saturated (backpressure applied)",
                retry_after=1.0,
            )

        event = IngestionEvent(
            event_id=event_id,
            tenant_id=tenant_id,
            payload=payload,
            headers=headers,
            created_at=asyncio.get_event_loop().time(),
            metadata=metadata or {},
        )

        try:
            self._queue.put_nowait(event)
        except asyncio.QueueFull:
            return IngestionResult(
                status="overloaded",
                event_id=event_id,
                message="Pipeline queue is saturated (backpressure applied)",
                retry_after=1.0,
            )

        return IngestionResult(
            status="accepted",
            event_id=event_id,
            message="Event accepted and queued for asynchronous processing",
        )

    async def shutdown(self, drain: bool = True, timeout: float = 5.0) -> None:
        """
        Gracefully stop pipeline workers.
        
        :param drain: If True, waits for remaining queued events to be processed.
        :param timeout: Maximum seconds to wait during drain.
        """
        self._draining = drain
        self._running = False

        if drain:
            try:
                await asyncio.wait_for(self._queue.join(), timeout=timeout)
            except asyncio.TimeoutError:
                logger.warning(f"Drain timed out after {timeout}s; terminating workers.")

        for worker in self._workers:
            if not worker.done():
                worker.cancel()

        await asyncio.gather(*self._workers, return_exceptions=True)
        self._draining = False
        logger.info("IngestionPipeline shutdown complete.")
