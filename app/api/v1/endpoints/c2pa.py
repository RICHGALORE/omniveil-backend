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


router = APIRouter(prefix="/c2pa", tags=["C2PA"])


@router.post("/read")
async def read_uploaded_c2pa(
    file: UploadFile = File(...),
    tenant: Client = Depends(resolve_tenant),
):
    """Read/validate Content Credentials without registering the uploaded file."""
    del tenant  # authentication gate; C2PA result itself is tenant-independent
    data = await file.read()
    suffix = Path(file.filename or "asset").suffix[:12]
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as temp:
            temp.write(data)
            temp_path = temp.name
        return {
            "filename": file.filename,
            "size_bytes": len(data),
            "c2pa": read_c2pa_path(temp_path),
        }
    finally:
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError:
                pass


@router.get("/assets/{omni_id}")
def read_registered_asset_c2pa(
    omni_id: str,
    tenant: Client = Depends(resolve_tenant),
    db: Session = Depends(get_db),
):
    """Read/validate C2PA evidence from the tenant's registered original asset."""
    asset = get_asset(db, omni_id, tenant.tenant_id)
    if not asset:
        raise HTTPException(404, "Asset not found")
    if not asset.original_path:
        raise HTTPException(409, "Registered asset has no original file path")
    if not Path(asset.original_path).exists():
        raise HTTPException(409, "Registered original file is not available on this storage node")

    return {
        "omni_id": asset.omni_id,
        "sha256": asset.sha256,
        "filename": asset.filename,
        "c2pa": read_c2pa_path(asset.original_path),
    }
