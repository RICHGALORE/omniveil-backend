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
from app.services.humanproof_public import (
    PUBLIC_SESSION_STATUSES,
    get_public_humanproof_summary as build_public_humanproof_summary,
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
    if not session:
        raise HTTPException(404, "HumanProof record not found")
    return session


def _public_evidence_summary(serialized: dict, privacy_mode: str) -> dict:
    """Build an explicit public-safe summary before raw event payloads are removed.

    The summary contains product values that belong on the HumanProof record art
    without exposing local paths, path tokens, raw creator notes, USB serials, or
    private source lineage identifiers in Proof mode.
    """
    events = serialized.get("events") or []
    started = next((event for event in events if event.get("event_type") == "session_started"), None)
    started_payload = (started or {}).get("payload") or {}

    workflow = started_payload.get("workflow")
    production_environment = (
        started_payload.get("daw_name")
        or started_payload.get("production_environment")
        or (started or {}).get("source_name")
    )

    connected_hardware: list[dict] = []
    seen_hardware: set[tuple[str, str]] = set()
    additional_apps: list[str] = []
    seen_apps: set[str] = set()
    automatic_revisions = 0
    automatic_exports = 0
    contributor_declarations = 0

    source_lineage = None
    transformations: list[str] = []
    transformation_statement = None
    final_provenance_disclosure = None

    for event in events:
        payload = event.get("payload") or {}
        checkpoint = payload.get("checkpoint")

        if checkpoint == "automatic_project_revision":
            automatic_revisions += 1
        if checkpoint == "automatic_audio_export":
            automatic_exports += 1
        if event.get("event_type") in {"contributor_declared", "contributor_attested"}:
            contributor_declarations += 1

        hardware = payload.get("connected_production_hardware") or []
        if isinstance(hardware, list):
            for item in hardware:
                if not isinstance(item, dict):
                    continue
                name = item.get("name")
                category = item.get("category")
                if not isinstance(name, str) or not name.strip():
                    continue
                safe_category = category if isinstance(category, str) else "production_hardware"
                key = (name.strip(), safe_category)
                if key in seen_hardware:
                    continue
                seen_hardware.add(key)
                connected_hardware.append({"name": key[0], "category": key[1]})

        apps = payload.get("process_only_environments") or []
        if isinstance(apps, list):
            for app in apps:
                if isinstance(app, str) and app.strip() and app.strip() not in seen_apps:
                    seen_apps.add(app.strip())
                    additional_apps.append(app.strip())

        if checkpoint == "source_asset_linked":
            source_lineage = {
                "present": True,
                "source_ai_disclosure": payload.get("source_ai_disclosure"),
                "source_ai_detection_score": payload.get("source_ai_detection_score"),
                "source_content_label": payload.get("source_content_label"),
                "source_omni_id": payload.get("source_omni_id") if privacy_mode == "public" else None,
                "history_preserved": payload.get("history_mutated") is False,
            }

        if checkpoint == "human_transformation_declared":
            declared = payload.get("transformations") or []
            if isinstance(declared, list):
                transformations = [value for value in declared if isinstance(value, str)]
            if privacy_mode == "public" and isinstance(payload.get("statement"), str):
                transformation_statement = payload.get("statement")

        if event.get("event_type") == "ai_tool_disclosed":
            value = payload.get("final_provenance_disclosure")
            if isinstance(value, str):
                final_provenance_disclosure = value

    transformation_verified = bool(source_lineage and transformations)
    return {
        "workflow": workflow,
        "production_environment": production_environment,
        "connected_production_hardware": connected_hardware,
        "additional_production_apps": additional_apps,
        "automatic_project_detected": any(
            (event.get("payload") or {}).get("checkpoint") == "automatic_project_detected"
            for event in events
        ),
        "automatic_revisions": automatic_revisions,
        "automatic_exports": automatic_exports,
        "contributor_declarations": contributor_declarations,
        "human_transformation": {
            "verified": transformation_verified,
            "source_lineage": source_lineage,
            "transformations": transformations,
            "statement": transformation_statement,
            "final_provenance_disclosure": final_provenance_disclosure,
        },
    }


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


@router.get("/assets/{omni_id}")
def get_humanproof_for_asset(
    omni_id: str,
    tenant: Client = Depends(resolve_tenant),
    db: Session = Depends(get_db),
):
    """Return the latest full HumanProof record for an authenticated tenant asset."""
    session = _latest_tenant_asset_session(db, omni_id, tenant.tenant_id)
    return serialize_session(db, session)


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
    """Return a creator-authorized sanitized public HumanProof timeline."""
    compact_summary = build_public_humanproof_summary(db, omni_id)
    if compact_summary is None:
        # A private HumanProof session is deliberately indistinguishable from an
        # asset that has no public HumanProof record.
        raise HTTPException(404, "HumanProof record not found")

    session = (
        db.query(HumanProofSession)
        .filter(
            HumanProofSession.omni_id == omni_id,
            HumanProofSession.status.in_(PUBLIC_SESSION_STATUSES),
        )
        .order_by(HumanProofSession.closed_at.desc(), HumanProofSession.created_at.desc())
        .first()
    )
    if not session:
        raise HTTPException(404, "HumanProof record not found")

    summary = serialize_session(db, session, public=True)
    privacy_mode = compact_summary["privacy_mode"]
    summary["privacy_mode"] = privacy_mode
    summary["evidence_summary"] = _public_evidence_summary(summary, privacy_mode)

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
