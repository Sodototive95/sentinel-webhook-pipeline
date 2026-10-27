# sentinel-webhook-pipeline

[![CI Matrix](https://github.com/Sodototive95/sentinel-webhook-pipeline/actions/workflows/ci.yml/badge.svg)](https://github.com/Sodototive95/sentinel-webhook-pipeline/actions/workflows/ci.yml)
[![Python Version](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen.svg)](pyproject.toml)

High-throughput, crash-resilient asynchronous stream ingestion and webhook gateway in pure Python.

Engineered to protect backend services from burst traffic, timing attacks, replay tampering, and duplicate event execution under heavy operational load.

---

## 🏛️ Architecture Overview

```text
[ Incoming Webhook Stream (HTTP / JSON / Protobuf) ]
                        │
                        ▼
         ┌──────────────────────────────┐
         │ 1. Signature Verifier Gate   │ ──► Rejects forged signatures &
         │    - Constant-time HMAC      │     replay timestamps (> tolerance)
         │    - Stripe / GitHub / Hex   │
         └──────────────────────────────┘
                        │ (Valid)
                        ▼
         ┌──────────────────────────────┐
         │ 2. Tenant Rate Limiter       │ ──► Throttles abusive tenants
         │    - Token Bucket Algorithm  │     Returns Retry-After headers
         │    - Sliding Replenishment   │
         └──────────────────────────────┘
                        │ (Allowed)
                        ▼
         ┌──────────────────────────────┐
         │ 3. Idempotency Engine        │ ──► Rejects duplicate events
         │    - LRU Bounded Capacity    │     Prevents duplicate billing/state
         │    - TTL Sliding Window      │
         └──────────────────────────────┘
                        │ (Unique)
                        ▼
         ┌──────────────────────────────┐
         │ 4. Backpressure Queue Buffer │ ──► Applies graceful backpressure
         │    - Bounded asyncio.Queue   │     Protects memory from OOM crashes
         └──────────────────────────────┘
                        │
                        ▼
     ┌──────────────────────────────────────┐
     │ 5. Asynchronous Worker Pool          │
     │    - Concurrent worker tasks         │
     │    - POSIX SIGTERM graceful drain    │
     └──────────────────────────────────────┘
```

---

## ✨ Core Systems Features

* **Zero External Runtime Dependencies:** Written entirely with the Python 3.10+ standard library (`asyncio`, `hmac`, `hashlib`, `time`, `collections`).
* **Timing-Attack Immune:** Constant-time cryptographic comparison (`hmac.compare_digest`) prevents side-channel timing leaks.
* **Anti-Replay Protection:** Enforces configurable clock drift tolerance (e.g., Stripe timestamp headers) to eliminate replay attacks.
* **Multi-Format Signature Support:** Native verifiers for raw HMAC-SHA256 digests, GitHub `sha256=` headers, and Stripe `t=...,v1=...` signed timestamp payloads.
* **Bounded LRU Idempotency Engine:** Prevents duplicate event execution while bounding memory footprint via LRU eviction and TTL invalidation.
* **Per-Tenant Token Bucket Limiter:** Fractional token replenishment with burst headroom and RFC 6585 compliant `Retry-After` calculation.
* **Backpressure-Aware Worker Pool:** Graceful backpressure rejection (`HTTP 429 / 503`) under extreme queue saturation, preventing Out-Of-Memory (OOM) failures.
* **Zero-Loss Graceful Drain:** Clean shutdown handling (`SIGINT`/`SIGTERM`) draining pending queue items before worker termination.

---

## 🚀 Quickstart

### 1. Ingestion Pipeline Setup

```python
import asyncio
from sentinel_webhook import (
    SignatureVerifier,
    IdempotencyEngine,
    TokenBucketRateLimiter,
    IngestionPipeline,
    IngestionEvent,
)

async def event_handler(event: IngestionEvent):
    """Downstream business logic worker."""
    print(f"[Worker] Processing event: {event.event_id} for tenant {event.tenant_id}")
    # Simulate DB persist or async microservice dispatch
    await asyncio.sleep(0.05)

async def main():
    secret = "production_shared_webhook_secret_key"
    
    # 1. Initialize pipeline components
    verifier = SignatureVerifier(secret=secret, tolerance_seconds=300)
    idempotency = IdempotencyEngine(ttl_seconds=3600, max_capacity=50000)
    rate_limiter = TokenBucketRateLimiter(rate_per_second=50.0, burst_capacity=100.0)

    # 2. Start the pipeline with 4 background workers
    pipeline = IngestionPipeline(
        verifier=verifier,
        idempotency=idempotency,
        rate_limiter=rate_limiter,
        max_queue_size=1000,
        worker_count=4,
    )
    await pipeline.start(handler=event_handler)

    # 3. Ingest an incoming webhook payload
    payload = b'{"event":"charge.captured","amount_cents":4500}'
    sig = verifier.compute_hmac(payload)
    headers = {"x-signature-sha256": sig}

    result = await pipeline.submit(
        event_id="evt_01J98AB3X9K",
        tenant_id="tenant_acme_corp",
        payload=payload,
        headers=headers,
        signature_format="raw",
    )
    print(f"Submission status: {result.status}")  # "accepted"

    # 4. Graceful shutdown (drain in-flight events before exiting)
    await pipeline.shutdown(drain=True, timeout=5.0)

if __name__ == "__main__":
    asyncio.run(main())
```

---

## 🛡️ Security & Idempotency Specs

| Attack / Fault Mode | Defense Mechanism | Module |
| :--- | :--- | :--- |
| **Side-Channel Timing Attacks** | Constant-time digest equality comparison (`hmac.compare_digest`) | `signature.py` |
| **Replay Attacks** | Timestamp window drift tolerance enforcement | `signature.py` |
| **Network Retries / Duplicates** | SHA-256 fingerprinting & bounded LRU key registration | `idempotency.py` |
| **Noisy Neighbor / DDoS Bursts** | Per-tenant token bucket rate limiting with burst ceilings | `rate_limiter.py` |
| **Downstream DB Outage / OOM** | High-watermark bounded `asyncio.Queue` backpressure | `pipeline.py` |
| **Sudden Process Termination** | Controlled drain protocol on `SIGINT` / `SIGTERM` signals | `pipeline.py` |

---

## 🧪 Running Tests

The test suite requires no external test harness other than `pytest`:

```bash
# Clone the repository
git clone https://github.com/Sodototive95/sentinel-webhook-pipeline.git
cd sentinel-webhook-pipeline

# Run the test suite
python3 -m pytest -v
```

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
