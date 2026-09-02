from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.tenant import resolve_tenant
from app.db import get_asset
from app.db.models import Client
from app.db.session import get_db
from app.services.evidence_graph import build_evidence_graph
from app.services.humanproof_public import get_public_humanproof_summary


router = APIRouter(prefix="/evidence", tags=["Omni Evidence Graph"])


@router.get("/assets/{omni_id}")
def get_asset_evidence_graph(
    omni_id: str,
    tenant: Client = Depends(resolve_tenant),
    db: Session = Depends(get_db),
):
    """Return the tenant-scoped Omni Evidence Graph for a registered asset.

    V1 deliberately keeps distinct evidence classes separate rather than
    converting declarations, rights claims, forensic observations, certificates,
    and HumanProof into one unsupported truth determination.
    """
    asset = get_asset(db, omni_id, tenant.tenant_id)
    if not asset:
        raise HTTPException(404, "Asset not found")

    humanproof = get_public_humanproof_summary(db, omni_id)
    return build_evidence_graph(db, asset, humanproof=humanproof)
