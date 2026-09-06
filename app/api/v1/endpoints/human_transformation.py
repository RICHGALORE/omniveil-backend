from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.tenant import resolve_tenant
from app.db.humanproof_models import HumanProofSession
from app.db.models import Asset, Client
from app.db.session import get_db
from app.services.humanproof import append_event, create_session, serialize_session


router = APIRouter(prefix="/human-transformation", tags=["Human Transformation"])

ALLOWED_TRANSFORMATIONS = {
    "re_recorded",
    "replayed",
    "rearranged",
    "edited",
    "lyrics_rewritten",
    "vocals_replaced",
    "instrumentation_replaced",
    "mix_rebuilt",
    "sound_design",
    "timing_changed",
    "pitch_changed",
    "structure_changed",
    "other",
}


class StartTransformationRequest(BaseModel):
    source_omni_id: str
    creator_id: str | None = None
    project_title: str | None = None
    production_environment: str | None = None
    privacy_mode: str = "proof"


class DeclareTransformationRequest(BaseModel):
    transformations: list[str] = Field(min_length=1)
    statement: str | None = None
    production_environment: str | None = None


def _tenant_session(db: Session, session_id: str, tenant_id: str) -> HumanProofSession:
    session = (
        db.query(HumanProofSession)
        .filter(
            HumanProofSession.session_id == session_id,
            HumanProofSession.tenant_id == tenant_id,
        )
        .first()
    )
    if not session:
        raise HTTPException(404, "Human Transformation session not found")
    return session


@router.post("/sessions", status_code=201)
def start_human_transformation(
    body: StartTransformationRequest,
    tenant: Client = Depends(resolve_tenant),
    db: Session = Depends(get_db),
):
    if body.privacy_mode not in {"private", "proof", "public"}:
        raise HTTPException(400, "privacy_mode must be private, proof, or public")

    source = (
        db.query(Asset)
        .filter(Asset.omni_id == body.source_omni_id, Asset.tenant_id == tenant.tenant_id)
        .first()
    )
    if not source:
        raise HTTPException(404, "Source asset not found for this tenant")

    session = create_session(
        db,
        tenant_id=tenant.tenant_id,
        creator_id=body.creator_id,
        source_type="human_transformation",
        source_name=body.production_environment or "Human Transformation",
        payload={
            "workflow": "Human Transformation v1",
            "project_title": body.project_title,
            "privacy_mode": body.privacy_mode,
            "source_history_policy": "preserve_original",
        },
    )

    append_event(
        db,
        session=session,
        event_type="source_captured",
        source_type="registry",
        source_name="Omni Veil Registry Bank",
        creator_id=body.creator_id,
        payload={
            "checkpoint": "source_asset_linked",
            "source_omni_id": source.omni_id,
            "source_sha256": source.sha256,
            "source_ai_disclosure": source.ai_disclosure,
            "source_ai_detection_score": source.ai_detection_score,
            "source_content_label": source.content_label,
            "source_filename": source.filename,
            "history_mutated": False,
            "statement": "Original source provenance preserved before human transformation begins.",
        },
    )
    db.commit()
    db.refresh(session)
    return serialize_session(db, session)


@router.post("/sessions/{session_id}/declare")
def declare_human_transformation(
    session_id: str,
    body: DeclareTransformationRequest,
    tenant: Client = Depends(resolve_tenant),
    db: Session = Depends(get_db),
):
    session = _tenant_session(db, session_id, tenant.tenant_id)
    normalized = list(dict.fromkeys(value.strip().lower() for value in body.transformations if value.strip()))
    if not normalized:
        raise HTTPException(400, "At least one transformation is required")
    unsupported = [value for value in normalized if value not in ALLOWED_TRANSFORMATIONS]
    if unsupported:
        raise HTTPException(400, f"Unsupported transformation: {unsupported[0]}")

    append_event(
        db,
        session=session,
        event_type="work_saved",
        source_type="human_transformation",
        source_name=body.production_environment or "Human Transformation",
        creator_id=session.created_by,
        payload={
            "checkpoint": "human_transformation_declared",
            "transformations": normalized,
            "statement": body.statement,
            "declaration_source": "creator",
            "does_not_erase_source_ai_history": True,
        },
    )
    db.commit()
    db.refresh(session)
    return serialize_session(db, session)
