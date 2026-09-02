import os
import tempfile
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy.orm import Session

from app.core.tenant import resolve_tenant
from app.db import get_asset
from app.db.models import Client
from app.db.session import get_db
from app.services.c2pa_intelligence import read_c2pa_path
from app.services.humanproof_public import get_public_humanproof_summary
from app.services.metadata_anomaly import compute_metadata_anomaly_score
from app.services.metadata_extraction import extract_metadata_service
from app.services.metadata_persistence import (
    ensure_anomaly_score,
    get_metadata_by_omni_id,
    split_layers,
)
from app.services.omnispectra import build_omnispectra_report
from app.utils import hive


router = APIRouter(prefix="/spectra", tags=["OmniSpectra"])


async def _detect_synthetic(data: bytes, mime_type: str) -> float | None:
    try:
        if mime_type.startswith("image/"):
            return await hive.detect_ai_image(data, mime_type)
        if mime_type.startswith("audio/"):
            return await hive.detect_ai_audio(data)
    except Exception:
        return None
    return None


def _detector_identity(score: float | None) -> tuple[str | None, str | None]:
    """Identify the evidence provider only when a detector result exists."""
    if score is None:
        return None, None
    metadata = hive.detector_metadata()
    return metadata.get("provider"), metadata.get("model")


def _read_temp_c2pa(data: bytes, filename: str | None) -> dict:
    suffix = Path(filename or "asset").suffix[:12]
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as temp:
            temp.write(data)
            temp_path = temp.name
        return read_c2pa_path(temp_path)
    finally:
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError:
                pass


@router.post("/scan")
async def scan_asset(
    file: UploadFile = File(...),
    tenant: Client = Depends(resolve_tenant),
):
    """Run an authenticated ad-hoc OmniSpectra scan without registering the file."""
    del tenant
    data = await file.read()
    mime_type = file.content_type or "application/octet-stream"

    extraction = extract_metadata_service(
        data,
        filename=file.filename,
        mime_type=mime_type,
    )
    raw, normalized, derived = split_layers(extraction)
    anomaly = compute_metadata_anomaly_score(
        raw=raw,
        normalized=normalized,
        derived=derived,
        mime_type=mime_type,
    )
    ai_score = await _detect_synthetic(data, mime_type)
    detector_provider, detector_model = _detector_identity(ai_score)
    c2pa = _read_temp_c2pa(data, file.filename)

    report = build_omnispectra_report(
        filename=file.filename,
        sha256=(normalized.get("hashes") or {}).get("sha256"),
        ai_detection_score=ai_score,
        detector_provider=detector_provider,
        detector_model=detector_model,
        anomaly=anomaly,
        c2pa=c2pa,
    )
    report["scan_mode"] = "ad_hoc"
    report["size_bytes"] = len(data)
    report["mime_type"] = mime_type
    return report


@router.get("/assets/{omni_id}")
def get_registered_spectra_report(
    omni_id: str,
    tenant: Client = Depends(resolve_tenant),
    db: Session = Depends(get_db),
):
    """Return the multi-signal OmniSpectra report for a registered tenant asset."""
    asset = get_asset(db, omni_id, tenant.tenant_id)
    if not asset:
        raise HTTPException(404, "Asset not found")

    anomaly = None
    metadata_record = get_metadata_by_omni_id(db, omni_id, tenant_id=tenant.tenant_id)
    if metadata_record is not None:
        stored = ensure_anomaly_score(db, metadata_record)
        anomaly = {
            "anomaly_score": stored.get("anomaly_score"),
            "flags": stored.get("flags") or [],
            "anomaly_summary": stored.get("anomaly_summary"),
            "engine_version": stored.get("engine_version"),
        }

    if asset.original_path and Path(asset.original_path).exists():
        c2pa = read_c2pa_path(asset.original_path)
    else:
        c2pa = {
            "manifest_present": None,
            "validation_state": "source_unavailable",
            "validation_status": [],
            "validation_error_count": 0,
        }

    humanproof = get_public_humanproof_summary(db, omni_id)
    detector_provider, detector_model = _detector_identity(asset.ai_detection_score)

    report = build_omnispectra_report(
        omni_id=asset.omni_id,
        filename=asset.filename,
        sha256=asset.sha256,
        ai_detection_score=asset.ai_detection_score,
        detector_provider=detector_provider,
        detector_model=detector_model,
        anomaly=anomaly,
        c2pa=c2pa,
        watermark_applied=asset.watermark_applied,
        watermark_visible=asset.watermark_visible,
        watermark_invisible=asset.watermark_invisible,
        humanproof=humanproof,
    )
    report["scan_mode"] = "registered"
    report["asset_type"] = asset.asset_type
    report["trust_score"] = asset.trust_score
    report["content_label"] = asset.content_label
    return report
