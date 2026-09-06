from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.tenant import resolve_tenant
from app.db.humanproof_models import HumanProofSession
from app.db.models import Client
from app.db.session import get_db
from app.services.humanproof_publication import (
    build_public_record,
    normalize_public_fields,
    publication_settings,
    set_publication_fields,
)


router = APIRouter(prefix="/humanproof-publication", tags=["HumanProof Publication"])


class PublicationRequest(BaseModel):
    fields: list[str] = Field(default_factory=list)


def _latest_tenant_asset_session(db: Session, omni_id: str, tenant_id: str) -> HumanProofSession:
    session = (
        db.query(HumanProofSession)
        .filter(
            HumanProofSession.omni_id == omni_id,
            HumanProofSession.tenant_id == tenant_id,
        )
        .order_by(HumanProofSession.closed_at.desc(), HumanProofSession.created_at.desc())
        .first()
    )
    if session is None:
        raise HTTPException(404, "HumanProof record not found")
    return session


@router.get("/assets/{omni_id}")
def get_humanproof_publication_settings(
    omni_id: str,
    tenant: Client = Depends(resolve_tenant),
    db: Session = Depends(get_db),
):
    session = _latest_tenant_asset_session(db, omni_id, tenant.tenant_id)
    return publication_settings(db, session)


@router.put("/assets/{omni_id}")
def update_humanproof_publication_settings(
    omni_id: str,
    body: PublicationRequest,
    tenant: Client = Depends(resolve_tenant),
    db: Session = Depends(get_db),
):
    session = _latest_tenant_asset_session(db, omni_id, tenant.tenant_id)
    try:
        normalize_public_fields(body.fields)
        set_publication_fields(db, session=session, fields=body.fields)
    except ValueError as exc:
        db.rollback()
        raise HTTPException(400, str(exc)) from exc
    return publication_settings(db, session)


@router.get("/assets/{omni_id}/public")
def get_creator_selected_public_humanproof(
    omni_id: str,
    db: Session = Depends(get_db),
):
    record = build_public_record(db, omni_id)
    if record is None:
        raise HTTPException(404, "HumanProof record not found")
    return record
