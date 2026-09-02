from fastapi import APIRouter, UploadFile, File, Depends, Request
from sqlalchemy.orm import Session
from datetime import datetime
import json, uuid

from app.db import get_db, get_asset, VerificationLog
from app.db.models import Asset
from app.services.humanproof_public import get_public_humanproof_summary
from app.utils.hashing import sha256_bytes, blake3_bytes
from app.utils.security import verify_file_hashes, detect_provenance_mismatch, hash_log_entry

router = APIRouter(prefix="/verify", tags=["verify"])


# ── Internal helpers ─────────────────────────────────────────────────────────

def _write_log(
    db: Session,
    omni_id: str | None,
    check_type: str,
    result: str,
    details: dict,
    verified_by: str | None = None,
) -> None:
    """Append an immutable verification log entry."""
    now = datetime.utcnow()
    log_id = str(uuid.uuid4())
    log_data = {
        "log_id": log_id,
        "omni_id": omni_id,
        "check_type": check_type,
        "result": result,
        "details_json": json.dumps(details, default=str),
        "verified_by": verified_by,
        "timestamp": now.isoformat(),
    }
    db.add(VerificationLog(
        log_id=log_id,
        omni_id=omni_id,
        check_type=check_type,
        result=result,
        details_json=log_data["details_json"],
        verified_by=verified_by,
        timestamp=now,
        log_hash=hash_log_entry(log_data),
    ))
    db.commit()


def _requester_ip(request: Request | None) -> str | None:
    if request is None:
        return None
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return getattr(request.client, "host", None)


# ── POST /verify/file ─────────────────────────────────────────────────────────

@router.post("/file")
async def verify_file(
    request: Request,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    data = await file.read()
    computed_sha256 = sha256_bytes(data)
    ip = _requester_ip(request)

    asset: Asset | None = db.query(Asset).filter(Asset.sha256 == computed_sha256).first()

    if not asset:
        _write_log(db, None, "file_hash", "fail",
                   {"sha256": computed_sha256, "filename": file.filename}, ip)
        return {
            "verified": False,
            "sha256": computed_sha256,
            "message": "No matching asset found in Omni Veil registry.",
        }

    hash_result = verify_file_hashes(data, asset.sha256, asset.blake3)
    result_str = "pass" if hash_result["verified"] else "fail"
    _write_log(db, asset.omni_id, "file_hash", result_str, hash_result, ip)

    asset.total_verifications += 1
    db.commit()

    return {
        "verified": hash_result["verified"],
        "omni_id": asset.omni_id,
        "sha256": computed_sha256,
        "blake3_match": hash_result.get("blake3_match"),
        "trust_score": asset.trust_score,
        "content_label": asset.content_label,
        "creator_name": asset.creator_name,
        "created_at": asset.created_at.isoformat() if asset.created_at else None,
        "humanproof": get_public_humanproof_summary(db, asset.omni_id),
        "message": (
            "Asset verified in Omni Veil registry."
            if hash_result["verified"]
            else "Hash mismatch — file may have been modified."
        ),
    }


# ── POST /verify/hash ─────────────────────────────────────────────────────────

@router.post("/hash")
async def verify_hash(
    request: Request,
    payload: dict,
    db: Session = Depends(get_db),
):
    sha256 = (payload.get("sha256") or "").strip()
    if not sha256:
        return {"verified": False, "message": "sha256 is required"}

    ip = _requester_ip(request)
    asset: Asset | None = db.query(Asset).filter(Asset.sha256 == sha256).first()

    if not asset:
        _write_log(db, None, "file_hash", "fail", {"sha256": sha256}, ip)
        return {
            "verified": False,
            "sha256": sha256,
            "message": "No matching asset found in Omni Veil registry.",
        }

    _write_log(db, asset.omni_id, "file_hash", "pass", {"sha256": sha256}, ip)
    asset.total_verifications += 1
    db.commit()

    return {
        "verified": True,
        "omni_id": asset.omni_id,
        "sha256": sha256,
        "trust_score": asset.trust_score,
        "content_label": asset.content_label,
        "creator_name": asset.creator_name,
        "created_at": asset.created_at.isoformat() if asset.created_at else None,
        "humanproof": get_public_humanproof_summary(db, asset.omni_id),
        "message": "Asset verified in Omni Veil registry.",
    }


# ── GET /verify/{omni_id} ─────────────────────────────────────────────────────

@router.get("/{omni_id}")
async def verify_omni_id(
    omni_id: str,
    request: Request,
    db: Session = Depends(get_db),
):
    ip = _requester_ip(request)
    asset: Asset | None = get_asset(db, omni_id)

    if not asset:
        _write_log(db, omni_id, "omni_id", "fail",
                   {"omni_id": omni_id, "reason": "not_found"}, ip)
        return {
            "verified": False,
            "omni_id": omni_id,
            "message": "Asset not found in Omni Veil registry.",
        }

    # Manifest integrity check
    manifest_valid: bool | None = None
    manifest_mismatches: list[str] = []
    if asset.manifest_path:
        try:
            with open(asset.manifest_path) as f:
                manifest_data = json.load(f)
            manifest_mismatches = detect_provenance_mismatch(asset, manifest_data)
            manifest_valid = len(manifest_mismatches) == 0
        except Exception as e:
            manifest_valid = None
            manifest_mismatches = [f"Manifest read error: {e}"]

    result_str = "pass" if manifest_valid is not False else "warning"
    _write_log(db, omni_id, "omni_id", result_str, {
        "manifest_valid": manifest_valid,
        "mismatches": manifest_mismatches,
    }, ip)

    asset.total_verifications += 1
    db.commit()

    label_reasons = json.loads(asset.label_reasons or "[]")

    return {
        "verified": True,
        "omni_id": asset.omni_id,
        "asset_id": asset.asset_id,
        "filename": asset.filename,
        "file_type": asset.file_type,
        "trust_score": asset.trust_score,
        "content_label": asset.content_label,
        "label_reasons": label_reasons,
        "ai_disclosure": asset.ai_disclosure,
        "sha256": asset.sha256,
        "blake3": asset.blake3,
        "phash": asset.phash,
        "creator_name": asset.creator_name,
        "copyright_owner": asset.copyright_owner,
        "license_type": asset.license_type,
        "watermark_applied": asset.watermark_applied,
        "watermark_visible": asset.watermark_visible,
        "watermark_invisible": asset.watermark_invisible,
        "manifest_valid": manifest_valid,
        "manifest_mismatches": manifest_mismatches,
        "total_verifications": asset.total_verifications,
        "created_at": asset.created_at.isoformat() if asset.created_at else None,
        "registry_url": asset.registry_url,
        "humanproof": get_public_humanproof_summary(db, asset.omni_id),
        "message": "Asset verified in Omni Veil registry.",
    }
