"""
Tamper-resistant provenance security functions.

All hashing uses SHA-256 (stdlib) so there are no extra dependencies.
HMAC-SHA256 is used for certificate signing — deterministic and verifiable
without a PKI.
"""

import hashlib
import hmac
import json
import os
from typing import Optional

SIGNING_SECRET = os.getenv("OV_SIGNING_SECRET", "omni-veil-signing-secret-change-in-prod")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _canonical_json(data: dict) -> bytes:
    """Stable, deterministic JSON encoding (sorted keys, no extra whitespace)."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), default=str).encode()


# ---------------------------------------------------------------------------
# Provenance event integrity
# ---------------------------------------------------------------------------

def hash_event(event_data: dict) -> str:
    """
    SHA-256 of the event content (excluding its own hash field).
    Store in ProvenanceEvent.event_hash to detect row-level tampering.
    """
    payload = {k: v for k, v in event_data.items() if k != "event_hash"}
    return hashlib.sha256(_canonical_json(payload)).hexdigest()


# ---------------------------------------------------------------------------
# Certificate signing
# ---------------------------------------------------------------------------

def sign_certificate(cert_data: dict) -> str:
    """HMAC-SHA256 signature over the certificate payload (excluding 'signature')."""
    payload = {k: v for k, v in cert_data.items() if k != "signature"}
    return hmac.new(
        SIGNING_SECRET.encode(),
        _canonical_json(payload),
        hashlib.sha256,
    ).hexdigest()


def verify_certificate_signature(cert_data: dict, expected_signature: str) -> bool:
    """Return True only if the HMAC of cert_data matches expected_signature."""
    actual = sign_certificate(cert_data)
    return hmac.compare_digest(actual, expected_signature)


# ---------------------------------------------------------------------------
# Manifest integrity
# ---------------------------------------------------------------------------

def compute_manifest_hash(manifest_data: dict) -> str:
    """SHA-256 of the manifest JSON — embed inside the manifest under 'manifest_hash'."""
    payload = {k: v for k, v in manifest_data.items() if k != "manifest_hash"}
    return hashlib.sha256(_canonical_json(payload)).hexdigest()


# ---------------------------------------------------------------------------
# File hash verification
# ---------------------------------------------------------------------------

def verify_file_hashes(
    data: bytes,
    expected_sha256: str,
    expected_blake3: Optional[str] = None,
) -> dict:
    """
    Recompute SHA-256 (and optionally BLAKE3) from raw bytes and compare
    against stored values.  Returns a result dict with match booleans.
    """
    from app.utils.hashing import sha256_bytes, blake3_bytes

    actual_sha256 = sha256_bytes(data)
    result: dict = {
        "sha256_match": actual_sha256 == expected_sha256,
        "actual_sha256": actual_sha256,
        "expected_sha256": expected_sha256,
    }
    if expected_blake3:
        actual_blake3 = blake3_bytes(data)
        result["blake3_match"] = actual_blake3 == expected_blake3
        result["actual_blake3"] = actual_blake3
        result["expected_blake3"] = expected_blake3

    result["verified"] = result["sha256_match"] and result.get("blake3_match", True)
    return result


# ---------------------------------------------------------------------------
# Provenance mismatch detection
# ---------------------------------------------------------------------------

def detect_provenance_mismatch(asset, manifest_data: dict) -> list[str]:
    """
    Compare a manifest JSON dict against the DB Asset record.
    Returns a list of human-readable mismatch descriptions (empty = clean).
    """
    mismatches: list[str] = []

    checks = [
        ("omni_id", asset.omni_id),
        ("sha256", asset.sha256),
        ("blake3", asset.blake3),
        ("filename", asset.filename),
    ]
    for field, db_val in checks:
        manifest_val = manifest_data.get(field)
        if manifest_val is not None and manifest_val != db_val:
            mismatches.append(
                f"{field} mismatch — manifest: {manifest_val!r}, db: {db_val!r}"
            )

    return mismatches


# ---------------------------------------------------------------------------
# Verification log integrity
# ---------------------------------------------------------------------------

def hash_log_entry(log_data: dict) -> str:
    """
    SHA-256 of the log entry (excluding its own hash field).
    Store in VerificationLog.log_hash to preserve audit-trail integrity.
    """
    payload = {k: v for k, v in log_data.items() if k != "log_hash"}
    return hashlib.sha256(_canonical_json(payload)).hexdigest()
