"""
sentinel_webhook
~~~~~~~~~~~~~~~~
High-throughput, crash-resilient asynchronous stream ingestion and webhook gateway.
"""

from .idempotency import DuplicateEventError, IdempotencyEngine
from .pipeline import (
    HandlerFunc,
    IngestionEvent,
    IngestionPipeline,
    IngestionResult,
    PipelineClosedError,
    PipelineOverloadedError,
)
from .rate_limiter import BucketState, RateLimitExceededError, TokenBucketRateLimiter
from .signature import (
    ExpiredTimestampError,
    InvalidSignatureError,
    MissingHeaderError,
    SignatureVerificationError,
    SignatureVerifier,
)

__version__ = "0.1.0"
__all__ = [
    "SignatureVerifier",
    "SignatureVerificationError",
    "InvalidSignatureError",
    "ExpiredTimestampError",
    "MissingHeaderError",
    "IdempotencyEngine",
    "DuplicateEventError",
    "TokenBucketRateLimiter",
    "RateLimitExceededError",
    "BucketState",
    "IngestionPipeline",
    "IngestionEvent",
    "IngestionResult",
    "PipelineOverloadedError",
    "PipelineClosedError",
    "HandlerFunc",
]
