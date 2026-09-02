from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.tenant import resolve_tenant
from app.db.humanproof_models import HumanProofSession
from app.db.models import Client
from app.db.session import get_db
from app.services.humanproof import (
    ALLOWED_EVENT_TYPES,
    append_event,
    close_session,
    create_session,
    serialize_session,
    verify_session_chain,
)

router = APIRouter(prefix="/humanproof", tags=["HumanProof"])


class StartSessionRequest(BaseModel):
    creator_id: str | None = None
    source_type: str = "web"
    source_name: str | None = None
    occurred_at: datetime | None = None
    location: dict | None = None
    payload: dict = Field(default_factory=dict)


class EvidenceEventRequest(BaseModel):
    event_type: str
    source_type: str = "web"
    source_name: str | None = None
    creator_id: str | None = None
    occurred_at: datetime | None = None
    ai_disclosure: dict | None = None
    location: dict | None = None
    payload: dict = Field(default_factory=dict)
    omni_id: str | None = None


class CloseSessionRequest(BaseModel):
    source_type: str = "web"
    source_name: str | None = None
    creator_id: str | None = None
    occurred_at: datetime | None = None


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
        raise HTTPException(404, "HumanProof session not found")
    return session


@router.post("/sessions", status_code=201)
def start_humanproof_session(
    body: StartSessionRequest,
    tenant: Client = Depends(resolve_tenant),
    db: Session = Depends(get_db),
):
    try:
        session = create_session(
            db,
            tenant_id=tenant.tenant_id,
            creator_id=body.creator_id,
            source_type=body.source_type,
            source_name=body.source_name,
            occurred_at=body.occurred_at,
            location=body.location,
            payload=body.payload,
        )
    except ValueError as exc:
        db.rollback()
        raise HTTPException(400, str(exc)) from exc
    return serialize_session(db, session)


@router.get("/sessions")
def list_humanproof_sessions(
    limit: int = 50,
    tenant: Client = Depends(resolve_tenant),
    db: Session = Depends(get_db),
):
    sessions = (
        db.query(HumanProofSession)
        .filter(HumanProofSession.tenant_id == tenant.tenant_id)
        .order_by(HumanProofSession.created_at.desc())
        .limit(limit)
        .all()
    )
    return {
        "items": [serialize_session(db, session) for session in sessions],
        "total": len(sessions),
    }


@router.get("/sessions/{session_id}")
def get_humanproof_session(
    session_id: str,
    tenant: Client = Depends(resolve_tenant),
    db: Session = Depends(get_db),
):
    return serialize_session(db, _tenant_session(db, session_id, tenant.tenant_id))


@router.post("/sessions/{session_id}/events", status_code=201)
def add_humanproof_event(
    session_id: str,
    body: EvidenceEventRequest,
    tenant: Client = Depends(resolve_tenant),
    db: Session = Depends(get_db),
):
    if body.event_type not in ALLOWED_EVENT_TYPES:
        raise HTTPException(400, "Unsupported HumanProof event type")
    if body.event_type == "ai_tool_disclosed":
        if not isinstance(body.ai_disclosure, dict) or not isinstance(body.ai_disclosure.get("used"), bool):
            raise HTTPException(400, "AI disclosure requires explicit used: true or false")

    session = _tenant_session(db, session_id, tenant.tenant_id)
    try:
        append_event(
            db,
            session=session,
            event_type=body.event_type,
            source_type=body.source_type,
            source_name=body.source_name,
            creator_id=body.creator_id,
            occurred_at=body.occurred_at,
            ai_disclosure=body.ai_disclosure,
            location=body.location,
            payload=body.payload,
            omni_id=body.omni_id,
        )
        db.commit()
        db.refresh(session)
    except ValueError as exc:
        db.rollback()
        raise HTTPException(400, str(exc)) from exc
    return serialize_session(db, session)


@router.post("/sessions/{session_id}/close")
def close_humanproof_session(
    session_id: str,
    body: CloseSessionRequest,
    tenant: Client = Depends(resolve_tenant),
    db: Session = Depends(get_db),
):
    session = _tenant_session(db, session_id, tenant.tenant_id)
    try:
        session, result = close_session(
            db,
            session=session,
            source_type=body.source_type,
            source_name=body.source_name,
            creator_id=body.creator_id,
            occurred_at=body.occurred_at,
        )
    except ValueError as exc:
        db.rollback()
        raise HTTPException(400, str(exc)) from exc
    return {**serialize_session(db, session), "completion": result}


@router.get("/sessions/{session_id}/verify")
def verify_humanproof_session(
    session_id: str,
    tenant: Client = Depends(resolve_tenant),
    db: Session = Depends(get_db),
):
    session = _tenant_session(db, session_id, tenant.tenant_id)
    return {
        "session_id": session.session_id,
        "status": session.status,
        "chain_integrity": verify_session_chain(db, session),
    }


@router.get("/assets/{omni_id}/public")
def get_public_humanproof_summary(
    omni_id: str,
    db: Session = Depends(get_db),
):
    session = (
        db.query(HumanProofSession)
        .filter(
            HumanProofSession.omni_id == omni_id,
            HumanProofSession.status.in_(["complete", "integrity_failed", "incomplete"]),
        )
        .order_by(HumanProofSession.closed_at.desc())
        .first()
    )
    if not session:
        raise HTTPException(404, "HumanProof record not found")

    summary = serialize_session(db, session, public=True)
    for event in summary["events"]:
        # Public HumanProof exposes cryptographic continuity and safe disclosure
        # summaries, not the creator's raw workflow evidence.
        event.pop("payload", None)
        event.pop("source_name", None)
        event.pop("creator_id", None)

        location = event.get("location")
        if location and location.get("level") == "coarse":
            public_summary = location.get("public_summary")
            event["location"] = (
                {"level": "coarse", "public_summary": public_summary}
                if public_summary
                else {"level": "coarse"}
            )
    return summary
