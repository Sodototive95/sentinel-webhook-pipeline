"""
sentinel_webhook.signature
~~~~~~~~~~~~~~~~~~~~~~~~~~
Cryptographic HMAC-SHA256 signature verification with constant-time equality
checking and anti-replay timestamp validation.
"""

from __future__ import annotations

import hashlib
import hmac
import time
from typing import Mapping, Optional


class SignatureVerificationError(Exception):
    """Base exception for signature verification failures."""
    pass


class InvalidSignatureError(SignatureVerificationError):
    """Raised when the calculated signature does not match the provided signature."""
    pass


class ExpiredTimestampError(SignatureVerificationError):
    """Raised when a signature timestamp exceeds the allowed drift tolerance."""
    pass


class MissingHeaderError(SignatureVerificationError):
    """Raised when required signature or timestamp headers are missing."""
    pass


class SignatureVerifier:
    """
    High-assurance HMAC-SHA256 signature verification engine.
    
    Supports:
    - Standard raw hex HMAC signatures.
    - GitHub-style prefix headers (`sha256=HEX_DIGEST`).
    - Stripe-style signed timestamp payloads (`t=TIMESTAMP,v1=HEX_DIGEST`).
    - Constant-time validation via `hmac.compare_digest` to prevent timing attacks.
    - Configurable anti-replay timestamp tolerance windows.
    """

    def __init__(
        self,
        secret: bytes | str,
        tolerance_seconds: int = 300,
    ) -> None:
        """
        Initialize the verifier.
        
        :param secret: Shared secret key for HMAC computation.
        :param tolerance_seconds: Maximum allowed clock drift in seconds (default 300s).
        """
        if isinstance(secret, str):
            self.secret = secret.encode("utf-8")
        elif isinstance(secret, bytes):
            self.secret = secret
        else:
            raise TypeError("Secret must be bytes or str")

        if tolerance_seconds <= 0:
            raise ValueError("tolerance_seconds must be positive")

        self.tolerance_seconds = tolerance_seconds

    def compute_hmac(self, data: bytes) -> str:
        """Compute the hexadecimal HMAC-SHA256 digest of data using the shared secret."""
        return hmac.new(self.secret, data, hashlib.sha256).hexdigest()

    def verify_raw(self, payload: bytes, signature_hex: str) -> bool:
        """
        Verify raw payload against an expected hexadecimal HMAC-SHA256 digest.
        Uses constant-time comparison to prevent side-channel timing leaks.
        """
        if not signature_hex or not isinstance(signature_hex, str):
            raise InvalidSignatureError("Signature must be a non-empty string")

        expected = self.compute_hmac(payload)
        if not hmac.compare_digest(expected, signature_hex.strip()):
            raise InvalidSignatureError("Signature mismatch")
        return True

    def verify_github(
        self,
        payload: bytes,
        signature_header: str,
    ) -> bool:
        """
        Verify GitHub-style webhook payload: `X-Hub-Signature-256: sha256=<hex>`.
        """
        if not signature_header:
            raise MissingHeaderError("Missing GitHub signature header")

        parts = signature_header.strip().split("=", 1)
        if len(parts) != 2 or parts[0] != "sha256":
            raise InvalidSignatureError(f"Invalid signature header format: {signature_header}")

        sig_hex = parts[1]
        return self.verify_raw(payload, sig_hex)

    def verify_stripe(
        self,
        payload: bytes,
        signature_header: str,
        current_time: Optional[float] = None,
    ) -> bool:
        """
        Verify Stripe-style signed webhook: `Stripe-Signature: t=<timestamp>,v1=<hex>`.
        Protects against replay attacks by verifying timestamp is within tolerance.
        """
        if not signature_header:
            raise MissingHeaderError("Missing Stripe signature header")

        now = current_time if current_time is not None else time.time()
        parsed_items: dict[str, list[str]] = {}

        for item in signature_header.strip().split(","):
            kv = item.split("=", 1)
            if len(kv) == 2:
                k, v = kv[0].strip(), kv[1].strip()
                parsed_items.setdefault(k, []).append(v)

        if "t" not in parsed_items or not parsed_items["t"]:
            raise MissingHeaderError("Missing timestamp 't' in signature header")
        if "v1" not in parsed_items or not parsed_items["v1"]:
            raise MissingHeaderError("Missing signature 'v1' in signature header")

        try:
            timestamp = int(parsed_items["t"][0])
        except ValueError:
            raise InvalidSignatureError("Invalid timestamp format in signature header")

        # Anti-replay check
        if abs(now - timestamp) > self.tolerance_seconds:
            raise ExpiredTimestampError(
                f"Timestamp {timestamp} drifts {abs(now - timestamp):.1f}s, exceeding tolerance {self.tolerance_seconds}s"
            )

        # In Stripe spec: signed_payload = f"{timestamp}.{payload}"
        signed_payload = f"{timestamp}.".encode("utf-8") + payload
        expected_sig = self.compute_hmac(signed_payload)

        # Check all v1 signatures in header (support rotation)
        valid = any(hmac.compare_digest(expected_sig, candidate) for candidate in parsed_items["v1"])
        if not valid:
            raise InvalidSignatureError("No matching valid v1 signature found")
        return True
