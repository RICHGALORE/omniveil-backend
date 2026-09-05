from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.tenant import resolve_tenant
from app.db import get_asset
from app.db.models import Client
from app.db.session import get_db
from app.services.fact_integrity import build_fact_integrity_report


router = APIRouter(tags=["integrity"])


@router.get("/assets/{omni_id}/integrity")
def get_asset_integrity(
    omni_id: str,
    tenant: Client = Depends(resolve_tenant),
    db: Session = Depends(get_db),
):
    """Compare persisted asset facts against independent Omni Veil records.

    This endpoint is tenant-scoped and read-only. It reports consistency drift;
    it does not alter the asset and does not make legal or authenticity rulings.
    """
    asset = get_asset(db, omni_id, tenant.tenant_id)
    if not asset:
        raise HTTPException(404, "Asset not found")
    return build_fact_integrity_report(db, asset)
