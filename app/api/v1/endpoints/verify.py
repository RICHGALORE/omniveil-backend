from fastapi import APIRouter, UploadFile, File, Depends, Request
from sqlalchemy.orm import Session
from datetime import datetime
import json, uuid

from app.core.storage import resolve_stored_path
from app.db import get_db, get_asset, VerificationLog
from app.db.models import Asset
from app.services.asset_facts import asset_identity, trust_facts
from app.services.humanproof_public import get_public_humanproof_summary
from app.utils.hashing import sha256_bytes
from app.utils.security import verify_file_hashes, detect_provenance_mismatch, hash_log_entry

router = APIRouter(prefix="/verify", tags=["verify"])


def _write_log(
    db: Session,
    omni_id: str | None,
    check_type: str,
    result: str,
    details: dict,
    verified_by: str | None = None,
) -> None:
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


def _match_summary(asset: Asset) -> dict:
    identity = asset_identity(asset)
    trust = trust_facts(asset)
    return {
        "omni_id": identity["omni_id"],
        "filename": identity["filename"],
        "creator_name": identity["creator_name"],
        "created_at": identity["created_at"],
        "trust_score": trust["trust_score"],
        "content_label": trust["content_label"],
    }


def _assets_for_sha(db: Session, sha256: str) -> list[Asset]:
    return (
        db.query(Asset)
        .filter(Asset.sha256 == sha256)
        .order_by(Asset.created_at.asc(), Asset.omni_id.asc())
        .all()
    )


@router.post("/file")
async def verify_file(
    request: Request,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    data = await file.read()
    computed_sha256 = sha256_bytes(data)
    ip = _requester_ip(request)
    assets = _assets_for_sha(db, computed_sha256)

    if not assets:
        _write_log(db, None, "file_hash", "fail",
                   {"sha256": computed_sha256, "filename": file.filename}, ip)
        return {
            "verified": False,
            "sha256": computed_sha256,
            "message": "No matching asset found in Omni Veil registry.",
        }

    if len(assets) > 1:
        matches = _match_summaries_with_hash_check(assets, data)
        verified = any(item["hash_verified"] for item in matches)
        _write_log(db, None, "file_hash", "warning" if verified else "fail", {
            "sha256": computed_sha256,
            "filename": file.filename,
            "ambiguous": True,
            "matching_omni_ids": [item["omni_id"] for item in matches],
        }, ip)
        return {
            "verified": verified,
            "ambiguous": True,
            "sha256": computed_sha256,
            "match_count": len(matches),
            "matches": matches,
            "message": (
                "Multiple Omni Veil records match this file. Select the intended Omni ID "
                "to verify a specific registration."
            ),
        }

    asset = assets[0]
    hash_result = verify_file_hashes(data, asset.sha256, asset.blake3)
    result_str = "pass" if hash_result["verified"] else "fail"
    _write_log(db, asset.omni_id, "file_hash", result_str, hash_result, ip)

    asset.total_verifications = int(asset.total_verifications or 0) + 1
    db.commit()
    trust = trust_facts(asset)
    identity = asset_identity(asset)

    return {
        "verified": hash_result["verified"],
        "omni_id": asset.omni_id,
        "sha256": computed_sha256,
        "blake3_match": hash_result.get("blake3_match"),
        "trust_score": trust["trust_score"],
        "content_label": trust["content_label"],
        "creator_name": identity["creator_name"],
        "created_at": identity["created_at"],
        "total_verifications": trust_facts(asset)["total_verifications"],
        "humanproof": get_public_humanproof_summary(db, asset.omni_id),
        "message": (
            "Asset verified in Omni Veil registry."
            if hash_result["verified"]
            else "Hash mismatch — file may have been modified."
        ),
    }


def _match_summaries_with_hash_check(assets: list[Asset], data: bytes) -> list[dict]:
    matches = []
    for asset in assets:
        summary = _match_summary(asset)
        summary["hash_verified"] = verify_file_hashes(
            data, asset.sha256, asset.blake3
        )["verified"]
        matches.append(summary)
    return matches


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
    assets = _assets_for_sha(db, sha256)

    if not assets:
        _write_log(db, None, "file_hash", "fail", {"sha256": sha256}, ip)
        return {
            "verified": False,
            "sha256": sha256,
            "message": "No matching asset found in Omni Veil registry.",
        }

    if len(assets) > 1:
        matches = [_match_summary(asset) for asset in assets]
        _write_log(db, None, "file_hash", "warning", {
            "sha256": sha256,
            "ambiguous": True,
            "matching_omni_ids": [item["omni_id"] for item in matches],
        }, ip)
        return {
            "verified": True,
            "ambiguous": True,
            "sha256": sha256,
            "match_count": len(matches),
            "matches": matches,
            "message": (
                "This hash appears in multiple Omni Veil registrations. Select the intended "
                "Omni ID to verify a specific record."
            ),
        }

    asset = assets[0]
    _write_log(db, asset.omni_id, "file_hash", "pass", {"sha256": sha256}, ip)
    asset.total_verifications = int(asset.total_verifications or 0) + 1
    db.commit()
    identity = asset_identity(asset)
    trust = trust_facts(asset)

    return {
        "verified": True,
        "omni_id": asset.omni_id,
        "sha256": sha256,
        "trust_score": trust["trust_score"],
        "content_label": trust["content_label"],
        "creator_name": identity["creator_name"],
        "created_at": identity["created_at"],
        "total_verifications": trust["total_verifications"],
        "humanproof": get_public_humanproof_summary(db, asset.omni_id),
        "message": "Asset verified in Omni Veil registry.",
    }


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

    manifest_valid: bool | None = None
    manifest_mismatches: list[str] = []
    manifest_path = resolve_stored_path(asset.manifest_path)
    if manifest_path is not None:
        try:
            with manifest_path.open() as f:
                manifest_data = json.load(f)
            manifest_mismatches = detect_provenance_mismatch(asset, manifest_data)
            manifest_valid = len(manifest_mismatches) == 0
        except Exception as exc:
            manifest_valid = None
            manifest_mismatches = [f"Manifest read error: {type(exc).__name__}"]

    result_str = "pass" if manifest_valid is not False else "warning"
    _write_log(db, omni_id, "omni_id", result_str, {
        "manifest_valid": manifest_valid,
        "mismatches": manifest_mismatches,
    }, ip)

    asset.total_verifications = int(asset.total_verifications or 0) + 1
    db.commit()
    identity = asset_identity(asset)
    trust = trust_facts(asset)

    return {
        "verified": True,
        "omni_id": identity["omni_id"],
        "asset_id": identity["asset_id"],
        "filename": identity["filename"],
        "file_type": identity["file_type"],
        "trust_score": trust["trust_score"],
        "content_label": trust["content_label"],
        "label_reasons": trust["label_reasons"],
        "ai_disclosure": asset.ai_disclosure,
        "sha256": identity["sha256"],
        "blake3": identity["blake3"],
        "phash": identity["phash"],
        "creator_name": identity["creator_name"],
        "copyright_owner": asset.copyright_owner,
        "license_type": asset.license_type,
        "watermark_applied": trust["watermark_applied"],
        "watermark_visible": trust["watermark_visible"],
        "watermark_invisible": trust["watermark_invisible"],
        "manifest_valid": manifest_valid,
        "manifest_mismatches": manifest_mismatches,
        "total_verifications": trust["total_verifications"],
        "created_at": identity["created_at"],
        "registry_url": identity["registry_url"],
        "humanproof": get_public_humanproof_summary(db, asset.omni_id),
        "message": "Asset verified in Omni Veil registry.",
    }
