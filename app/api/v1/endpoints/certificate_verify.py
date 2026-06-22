from fastapi import APIRouter, HTTPException, Body
from pathlib import Path
from typing import Any, Dict
import json

from app.services.crypto_signing import verify_certificate_signature

router = APIRouter()

CERTIFICATES_DIR = Path("uploads/certificates")


def _load_certificate_by_omni_id(omni_id: str) -> Dict[str, Any]:
    certificate_path = CERTIFICATES_DIR / f"{omni_id}.json"

    if not certificate_path.exists():
        raise HTTPException(status_code=404, detail="Certificate not found")

    try:
        return json.loads(certificate_path.read_text())
    except Exception:
        raise HTTPException(status_code=500, detail="Certificate file is unreadable")


def _verify_signed_certificate(certificate: Dict[str, Any]) -> Dict[str, Any]:
    metadata = certificate.get("metadata_lock")

    if not metadata:
        return {
            "valid": False,
            "signature_valid": False,
            "metadata_valid": False,
            "certificate_hash_valid": False,
            "reason": "Certificate missing metadata_lock",
        }

    signature_valid = verify_certificate_signature(certificate, metadata)

    return {
        "valid": signature_valid,
        "signature_valid": signature_valid,
        "metadata_valid": signature_valid,
        "certificate_hash_valid": signature_valid,
        "signature_algorithm": certificate.get("signature_algorithm"),
        "public_key_id": certificate.get("public_key_id"),
        "certificate_hash": certificate.get("certificate_hash"),
        "metadata_hash": certificate.get("metadata_hash"),
        "omni_id": certificate.get("omni_id"),
        "cert_id": certificate.get("cert_id"),
        "issuer": certificate.get("issuer"),
    }


@router.get("/certificates/{omni_id}/verify")
async def verify_certificate_by_omni_id(omni_id: str):
    certificate = _load_certificate_by_omni_id(omni_id)
    return _verify_signed_certificate(certificate)


@router.post("/certificates/verify")
async def verify_certificate_payload(
    certificate: Dict[str, Any] = Body(...),
):
    return _verify_signed_certificate(certificate)
