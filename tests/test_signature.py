import time
import pytest
from sentinel_webhook.signature import (
    ExpiredTimestampError,
    InvalidSignatureError,
    MissingHeaderError,
    SignatureVerifier,
)

SECRET = "super_secret_webhook_key_12345"
PAYLOAD = b'{"event":"payment_intent.succeeded","amount":5000,"currency":"usd"}'


def test_raw_signature_verification():
    verifier = SignatureVerifier(SECRET)
    sig = verifier.compute_hmac(PAYLOAD)

    assert verifier.verify_raw(PAYLOAD, sig) is True

    # Tampered payload fails
    with pytest.raises(InvalidSignatureError):
        verifier.verify_raw(PAYLOAD + b"tampered", sig)

    # Forged signature fails
    with pytest.raises(InvalidSignatureError):
        verifier.verify_raw(PAYLOAD, "deadbeef" * 8)


def test_github_signature_verification():
    verifier = SignatureVerifier(SECRET)
    sig = verifier.compute_hmac(PAYLOAD)
    header = f"sha256={sig}"

    assert verifier.verify_github(PAYLOAD, header) is True

    # Missing header
    with pytest.raises(MissingHeaderError):
        verifier.verify_github(PAYLOAD, "")

    # Malformed prefix
    with pytest.raises(InvalidSignatureError):
        verifier.verify_github(PAYLOAD, f"sha1={sig}")


def test_stripe_signature_verification_and_replay_protection():
    verifier = SignatureVerifier(SECRET, tolerance_seconds=60)
    now = 1700000000.0

    # Valid Stripe signature
    signed_payload = f"{int(now)}.".encode("utf-8") + PAYLOAD
    sig = verifier.compute_hmac(signed_payload)
    header = f"t={int(now)},v1={sig}"

    assert verifier.verify_stripe(PAYLOAD, header, current_time=now) is True

    # Expired timestamp (replay attack)
    old_time = now - 120.0  # 120s old > 60s tolerance
    old_signed = f"{int(old_time)}.".encode("utf-8") + PAYLOAD
    old_sig = verifier.compute_hmac(old_signed)
    old_header = f"t={int(old_time)},v1={old_sig}"

    with pytest.raises(ExpiredTimestampError):
        verifier.verify_stripe(PAYLOAD, old_header, current_time=now)

    # Missing parts
    with pytest.raises(MissingHeaderError):
        verifier.verify_stripe(PAYLOAD, f"t={int(now)}", current_time=now)

    with pytest.raises(MissingHeaderError):
        verifier.verify_stripe(PAYLOAD, f"v1={sig}", current_time=now)
