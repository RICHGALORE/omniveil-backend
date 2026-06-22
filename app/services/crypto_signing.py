import base64
import hashlib
import json
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
}

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

    signed = dict(certificate_with_metadata_lock)
    signed["signature_algorithm"] = "Ed25519"
    signed["certificate_hash"] = cert_hash
    signed["signature"] = base64.b64encode(signature).decode("utf-8")
    signed["public_key"] = public_key_b64
    signed["public_key_id"] = public_key_id

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
