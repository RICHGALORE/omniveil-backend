import os
import tempfile
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.storage import resolve_stored_path
from app.core.tenant import resolve_tenant
from app.db import get_asset
from app.db.models import Client
from app.db.session import get_db
from app.services.c2pa_intelligence import read_c2pa_path
from app.services.forensic_observations import (
    get_forensic_observations,
    persist_forensic_observations,
)
from app.services.humanproof_public import get_public_humanproof_summary
from app.services.metadata_anomaly import compute_metadata_anomaly_score
from app.services.metadata_extraction import extract_metadata_service
from app.services.metadata_persistence import (
    ensure_anomaly_score,
    get_metadata_by_omni_id,
    split_layers,
)
from app.services.omnispectra import build_omnispectra_report
from app.services.synthetic_detection import (
    run_synthetic_detectors,
    sightengine_legacy_score,
)
from app.utils.upload_limits import read_upload_limited


router = APIRouter(prefix="/spectra", tags=["OmniSpectra"])


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


def _registered_report(db: Session, asset, tenant_id: str) -> dict:
    anomaly = None
    metadata_record = get_metadata_by_omni_id(db, asset.omni_id, tenant_id=tenant_id)
    if metadata_record is not None:
        stored = ensure_anomaly_score(db, metadata_record)
        anomaly = {
            "anomaly_score": stored.get("anomaly_score"),
            "flags": stored.get("flags") or [],
            "anomaly_summary": stored.get("anomaly_summary"),
            "engine_version": stored.get("engine_version"),
        }

    source_path = resolve_stored_path(asset.original_path)
    if source_path is not None and source_path.exists():
        c2pa = read_c2pa_path(str(source_path))
    else:
        c2pa = {
            "manifest_present": None,
            "validation_state": "source_unavailable",
            "validation_status": [],
            "validation_error_count": 0,
        }

    humanproof = get_public_humanproof_summary(db, asset.omni_id)
    detector_observations = get_forensic_observations(
        db,
        omni_id=asset.omni_id,
        tenant_id=tenant_id,
    )

    report = build_omnispectra_report(
        omni_id=asset.omni_id,
        filename=asset.filename,
        sha256=asset.sha256,
        # Historical assets persist Provider A in this compatibility column.
        ai_detection_score=asset.ai_detection_score,
        detector_provider="sightengine" if asset.ai_detection_score is not None else None,
        detector_model="genai" if asset.ai_detection_score is not None else None,
        detector_observations=detector_observations,
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


@router.post("/scan")
async def scan_asset(
    file: UploadFile = File(...),
    tenant: Client = Depends(resolve_tenant),
):
    """Run an authenticated ad-hoc OmniSpectra scan without registering the file."""
    del tenant
    data = await read_upload_limited(file, max_mb=settings.max_upload_mb)
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
    detector_observations = await run_synthetic_detectors(
        data,
        mime_type=mime_type,
        filename=file.filename,
    )
    legacy_score = sightengine_legacy_score(detector_observations)
    c2pa = _read_temp_c2pa(data, file.filename)

    report = build_omnispectra_report(
        filename=file.filename,
        sha256=(normalized.get("hashes") or {}).get("sha256"),
        ai_detection_score=legacy_score,
        detector_provider="sightengine" if legacy_score is not None else None,
        detector_model="genai" if legacy_score is not None else None,
        detector_observations=detector_observations,
        anomaly=anomaly,
        c2pa=c2pa,
    )
    report["scan_mode"] = "ad_hoc"
    report["size_bytes"] = len(data)
    report["mime_type"] = mime_type
    return report


@router.post("/assets/{omni_id}/detectors")
async def refresh_registered_detectors(
    omni_id: str,
    tenant: Client = Depends(resolve_tenant),
    db: Session = Depends(get_db),
):
    """Run configured external detectors on the immutable stored original.

    Results are appended as timestamped provider-specific observations. The
    original registration, certificate, creator declarations, legacy trust score,
    and persisted `assets.ai_detection_score` are never rewritten by a refresh.
    """
    asset = get_asset(db, omni_id, tenant.tenant_id)
    if not asset:
        raise HTTPException(404, "Asset not found")

    source_path = resolve_stored_path(asset.original_path)
    if source_path is None or not source_path.exists():
        raise HTTPException(409, "Registered source file is unavailable for detector refresh")

    data = source_path.read_bytes()
    observations = await run_synthetic_detectors(
        data,
        mime_type=asset.file_type or "application/octet-stream",
        filename=asset.filename or source_path.name,
    )
    if not observations:
        raise HTTPException(
            503,
            "No configured synthetic-media detector returned an observation",
        )

    rows = persist_forensic_observations(
        db,
        omni_id=asset.omni_id,
        tenant_id=tenant.tenant_id,
        observations=observations,
    )
    report = _registered_report(db, asset, tenant.tenant_id)
    report["detector_refresh"] = {
        "persisted_observation_count": len(rows),
        "providers": sorted({row.provider for row in rows}),
        "registration_rewritten": False,
        "trust_score_rewritten": False,
    }
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
    return _registered_report(db, asset, tenant.tenant_id)
