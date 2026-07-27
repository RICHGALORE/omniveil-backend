"""
Follow-up defect B — certificate signature verification.

The ingest pipeline appends `metadata_lock` and `legacy_hmac_signature` to the
certificate AFTER the Ed25519 signature is computed. Those fields must be
excluded when recomputing `certificate_hash` during verification, otherwise a
valid certificate is rejected. These tests prove the fix is cryptographically
correct — a genuine certificate verifies, and every form of tampering fails.
"""
import base64
import copy

from app.services import crypto_signing as cs


def _make_signed_certificate():
    """Reproduce the ingest signing flow, including the post-sign appends."""
    keys = cs.generate_ed25519_keypair()

    certificate = {
        "omni_id": "OV-TEST-0001",
        "cert_id": "cert-test-0001",
        "issuer": "Omni Veil Trust OS",
        "subject_name": "Alice Example",
        "certificate_class": "standard",
    }
    metadata = {
        "omni_id": "OV-TEST-0001",
        "sha256": "a" * 64,
        "creator_name": "Alice Example",
    }

    signed = cs.sign_certificate(
        certificate=certificate,
        metadata=metadata,
        private_key_b64=keys["private_key_b64"],
        public_key_b64=keys["public_key_b64"],
        public_key_id="OV-ROOT-DEV-001",
    )

    # Post-signing appends performed by ingest.py (Step 6 region).
    signed["metadata_lock"] = metadata
    signed["legacy_hmac_signature"] = "hmac-placeholder-not-part-of-ed25519"

    return signed, metadata


def test_valid_certificate_verifies():
    cert, metadata = _make_signed_certificate()
    assert cs.verify_certificate_signature(cert, metadata) is True


def test_tampered_metadata_fails():
    cert, metadata = _make_signed_certificate()
    tampered_metadata = copy.deepcopy(metadata)
    tampered_metadata["creator_name"] = "Mallory Attacker"
    # metadata_lock is also what the endpoint passes as `metadata`; tamper both
    # to simulate a forged metadata claim.
    cert["metadata_lock"] = tampered_metadata
    assert cs.verify_certificate_signature(cert, tampered_metadata) is False


def test_tampered_signature_fails():
    cert, metadata = _make_signed_certificate()
    raw = bytearray(base64.b64decode(cert["signature"]))
    raw[0] ^= 0xFF  # flip one byte
    cert["signature"] = base64.b64encode(bytes(raw)).decode("utf-8")
    assert cs.verify_certificate_signature(cert, metadata) is False


def test_certificate_hash_mismatch_fails():
    cert, metadata = _make_signed_certificate()
    # Tamper a signed content field so the recomputed certificate_hash no longer
    # matches the stored/signed certificate_hash.
    cert["subject_name"] = "Mallory Attacker"
    assert cs.verify_certificate_signature(cert, metadata) is False
