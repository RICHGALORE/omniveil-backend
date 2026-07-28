"""
Metadata Intelligence Engine — endpoints.

Commit 1 exposed a stateless extraction endpoint (``POST /metadata/extract``).
Commit 2 adds read endpoints for the durable, per-asset metadata persisted at
upload time. Persistence itself happens in the upload flow via the dedicated
persistence service; these endpoints are read-only and tenant-isolated.
"""
from fastapi import APIRouter, UploadFile, File, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.tenant import resolve_tenant
from app.db import get_db
from app.db.models import Client
from app.services.metadata_extraction import extract_metadata_service
from app.services.metadata_persistence import (
    get_metadata_by_omni_id,
    serialize_record,
    ensure_trust_score,
)

router = APIRouter(prefix="/metadata", tags=["metadata"])


@router.post("/extract")
async def extract_metadata(file: UploadFile = File(...)):
    """
    Extract comprehensive, normalized metadata from an uploaded asset.

    Input:  multipart/form-data file upload.
    Output: structured metadata JSON (see MetadataExtractionService).

    The service never raises on malformed / corrupt / empty input; extraction
    problems are reported inside the ``warnings`` field of the response.
    """
    data = await file.read()
    return extract_metadata_service(
        data,
        filename=file.filename,
        mime_type=file.content_type,
    )


@router.get("/assets/{omni_id}")
def get_asset_metadata(
    omni_id: str,
    tenant: Client = Depends(resolve_tenant),
    db: Session = Depends(get_db),
):
    """
    Return the persisted metadata record for ``omni_id`` belonging to the
    authenticated tenant. 404 if no record exists for this tenant (which also
    covers records owned by a different tenant — they are never disclosed).
    """
    record = get_metadata_by_omni_id(db, omni_id, tenant_id=tenant.tenant_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Metadata not found")
    return serialize_record(record)


@router.get("/assets/{omni_id}/raw")
def get_asset_metadata_raw(
    omni_id: str,
    tenant: Client = Depends(resolve_tenant),
    db: Session = Depends(get_db),
):
    """
    Return only the raw-extractor layer for ``omni_id`` (tenant-isolated).
    Kept minimal and separate from the full record for clean layer separation.
    """
    record = get_metadata_by_omni_id(db, omni_id, tenant_id=tenant.tenant_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Metadata not found")
    full = serialize_record(record)
    return {
        "omni_id": full["omni_id"],
        "asset_id": full["asset_id"],
        "engine_name": full["engine_name"],
        "engine_version": full["engine_version"],
        "extractor": full["extractor"],
        "metadata_sha256": full["metadata_sha256"],
        "raw_metadata": full["raw_metadata"],
    }


@router.get("/assets/{omni_id}/trust-score")
def get_asset_trust_score(
    omni_id: str,
    tenant: Client = Depends(resolve_tenant),
    db: Session = Depends(get_db),
):
    """
    Return the deterministic metadata trust score for ``omni_id`` (tenant-isolated).

    The score (0–100) is derived purely from the persisted metadata layers
    (normalized / raw / derived) — no uploaded bytes are re-read. It is computed
    and stored at persist time; this endpoint returns the stored score, lazily
    computing and persisting it once if a record predates the scoring engine.
    404 if no record exists for this tenant.
    """
    record = get_metadata_by_omni_id(db, omni_id, tenant_id=tenant.tenant_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Metadata not found")
    score = ensure_trust_score(db, record, include_explanations=True)
    return {
        "omni_id": record.omni_id,
        "overall": score["overall"],
        "breakdown": score["breakdown"],
        "explanations": score["explanations"],
        "engine_version": score["engine_version"],
        "analyzed_at": score["scored_at"],
    }
