import base64
import hashlib
import hmac
import json
import os
from typing import Any, Dict

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization

SIGNATURE_FIELDS = {
    "signature",
    "signature_algorithm",
    "certificate_hash",
    "metadata_hash",
    "public_key",
    "public_key_id",
    # Appended to the certificate by the ingest pipeline AFTER the Ed25519
    # signature is computed, so they are not part of the signed content and
    # must be excluded when recomputing certificate_hash during verification.
    "metadata_lock",
    "legacy_hmac_signature",
}


def _environment() -> str:
    return (
        os.getenv("ENVIRONMENT")
        or os.getenv("APP_ENV")
        or "development"
    ).strip().lower()


def canonical_json(data: Dict[str, Any]) -> bytes:
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def metadata_hash(metadata: Dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(metadata)).hexdigest()


def certificate_hash(certificate: Dict[str, Any]) -> str:
    unsigned = {
        key: value
        for key, value in certificate.items()
        if key not in SIGNATURE_FIELDS
    }
    return hashlib.sha256(canonical_json(unsigned)).hexdigest()


def generate_ed25519_keypair() -> Dict[str, str]:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )

    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    return {
        "private_key_b64": base64.b64encode(private_bytes).decode("utf-8"),
        "public_key_b64": base64.b64encode(public_bytes).decode("utf-8"),
    }


def load_private_key(private_key_b64: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(
        base64.b64decode(private_key_b64)
    )


def load_public_key(public_key_b64: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(
        base64.b64decode(public_key_b64)
    )


def sign_certificate(
    certificate: Dict[str, Any],
    metadata: Dict[str, Any],
    private_key_b64: str,
    public_key_b64: str,
    public_key_id: str = "OV-ROOT-DEV-001",
) -> Dict[str, Any]:

    meta_hash = metadata_hash(metadata)

    certificate_with_metadata_lock = dict(certificate)
    certificate_with_metadata_lock["metadata_hash"] = meta_hash

    cert_hash = certificate_hash(certificate_with_metadata_lock)

    private_key = load_private_key(private_key_b64)
    signature = private_key.sign(cert_hash.encode("utf-8"))

    # The current ingest caller still passes the historical development key ID.
    # Never allow that label to leak into a production certificate: production
    # must use the explicitly configured Trust Authority key ID.
    effective_key_id = public_key_id
    if _environment() == "production" and public_key_id == "OV-ROOT-DEV-001":
        effective_key_id = os.getenv("OV_SIGNING_KEY_ID", "").strip()
        if not effective_key_id:
            raise RuntimeError("Production certificate signing key ID is not configured.")

    signed = dict(certificate_with_metadata_lock)
    signed["signature_algorithm"] = "Ed25519"
    signed["certificate_hash"] = cert_hash
    signed["signature"] = base64.b64encode(signature).decode("utf-8")
    signed["public_key"] = public_key_b64
    signed["public_key_id"] = effective_key_id

    return signed


def verify_certificate_signature(
    certificate: Dict[str, Any],
    metadata: Dict[str, Any],
) -> bool:

    required = [
        "signature",
        "signature_algorithm",
        "certificate_hash",
        "metadata_hash",
        "public_key",
        "public_key_id",
    ]

    if any(field not in certificate for field in required):
        return False

    if certificate["signature_algorithm"] != "Ed25519":
        return False

    expected_metadata_hash = metadata_hash(metadata)
    if expected_metadata_hash != certificate["metadata_hash"]:
        return False

    expected_certificate_hash = certificate_hash(certificate)
    if expected_certificate_hash != certificate["certificate_hash"]:
        return False

    try:
        public_key = load_public_key(certificate["public_key"])
        signature = base64.b64decode(certificate["signature"])
        public_key.verify(
            signature,
            certificate["certificate_hash"].encode("utf-8")
        )
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Omni Veil Trust Authority key management
# ---------------------------------------------------------------------------

def _get_or_create_local_dev_keypair(
    path: str = ".secrets/ov_root_dev_keypair.json",
) -> Dict[str, str]:
    """Persistent development-only root keypair."""
    from pathlib import Path

    key_path = Path(path)
    key_path.parent.mkdir(parents=True, exist_ok=True)

    if key_path.exists():
        return json.loads(key_path.read_text())

    keys = generate_ed25519_keypair()
    key_path.write_text(json.dumps(keys, indent=2))
    return keys


def _derived_public_key_b64(private_key_b64: str) -> str:
    private_key = load_private_key(private_key_b64)
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(public_bytes).decode("utf-8")


def get_trust_signing_material(
    environment: str | None = None,
    dev_path: str = ".secrets/ov_root_dev_keypair.json",
) -> Dict[str, str]:
    """Return validated Trust Authority signing material.

    Development/test uses a persistent local root. Production fails closed
    unless an explicit Ed25519 keypair and key ID are provided via secrets, and
    verifies that the configured public key belongs to the configured private
    key. Production values must live in Render/KMS/secret storage, never Git.
    """
    env = (environment or _environment()).strip().lower()

    if env != "production":
        keys = _get_or_create_local_dev_keypair(dev_path)
        return {
            **keys,
            "public_key_id": "OV-ROOT-DEV-001",
            "environment": env,
        }

    private_key_b64 = os.getenv("OV_SIGNING_PRIVATE_KEY_B64", "").strip()
    public_key_b64 = os.getenv("OV_SIGNING_PUBLIC_KEY_B64", "").strip()
    public_key_id = os.getenv("OV_SIGNING_KEY_ID", "").strip()

    missing = [
        name
        for name, value in (
            ("OV_SIGNING_PRIVATE_KEY_B64", private_key_b64),
            ("OV_SIGNING_PUBLIC_KEY_B64", public_key_b64),
            ("OV_SIGNING_KEY_ID", public_key_id),
        )
        if not value
    ]
    if missing:
        raise RuntimeError(
            "Production certificate signing is not configured; missing: "
            + ", ".join(missing)
        )

    try:
        load_public_key(public_key_b64)
        derived_public = _derived_public_key_b64(private_key_b64)
    except Exception as exc:
        raise RuntimeError(
            "Production certificate signing key material is invalid."
        ) from exc

    if not hmac.compare_digest(derived_public, public_key_b64):
        raise RuntimeError(
            "Production certificate signing public/private keys do not match."
        )

    return {
        "private_key_b64": private_key_b64,
        "public_key_b64": public_key_b64,
        "public_key_id": public_key_id,
        "environment": "production",
    }


def get_or_create_dev_trust_keypair(
    path: str = ".secrets/ov_root_dev_keypair.json",
) -> Dict[str, str]:
    """Backward-compatible ingest hook with production fail-closed behavior.

    The name is historical. In production this function never creates or reads
    a development key; it returns only validated configured production keys.
    """
    material = get_trust_signing_material(dev_path=path)
    return {
        "private_key_b64": material["private_key_b64"],
        "public_key_b64": material["public_key_b64"],
    }
