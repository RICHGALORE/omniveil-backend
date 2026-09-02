import hashlib
import json
import uuid
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.db.humanproof_models import HumanProofEvent, HumanProofSession
from app.db.models import Asset


SCHEMA_VERSION = "1.0"
ALLOWED_EVENT_TYPES = {
    "session_started",
    "source_captured",
    "work_saved",
    "work_exported",
    "ai_tool_disclosed",
    "contributor_attested",
    "asset_registered",
    "session_closed",
}
ALLOWED_LOCATION_LEVELS = {"none", "coarse", "precise_private"}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _canonical_json(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _normalize_datetime(value: datetime | None) -> datetime:
    if value is None:
        return _utcnow()
    if value.tzinfo is not None:
        value = value.astimezone(timezone.utc).replace(tzinfo=None)
    return value


def _loads(value: str | None, default):
    if not value:
        return default
    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return default


def _event_evidence_dict(
    *,
    event_id: str,
    session_id: str,
    omni_id: str | None,
    sequence: int,
    event_type: str,
    occurred_at: datetime,
    recorded_at: datetime,
    previous_event_hash: str | None,
    source_type: str,
    source_name: str | None,
    creator_id: str | None,
    ai_disclosure: dict | None,
    location: dict | None,
    payload: dict,
    schema_version: str,
) -> dict:
    return {
        "event_id": event_id,
        "session_id": session_id,
        "omni_id": omni_id,
        "sequence": sequence,
        "event_type": event_type,
        "occurred_at": occurred_at.isoformat(timespec="microseconds") + "Z",
        "recorded_at": recorded_at.isoformat(timespec="microseconds") + "Z",
        "previous_event_hash": previous_event_hash,
        "source_type": source_type,
        "source_name": source_name,
        "creator_id": creator_id,
        "ai_disclosure": ai_disclosure,
        "location": location,
        "payload": payload,
        "schema_version": schema_version,
    }


def compute_event_hash(**kwargs) -> str:
    canonical = _canonical_json(_event_evidence_dict(**kwargs))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def validate_location(location: dict | None) -> dict | None:
    if location is None:
        return None
    level = location.get("level", "none")
    if level not in ALLOWED_LOCATION_LEVELS:
        raise ValueError("location.level must be none, coarse, or precise_private")
    if level == "precise_private":
        if "latitude" not in location or "longitude" not in location:
            raise ValueError("precise_private location requires latitude and longitude")
    return location


def create_session(
    db: Session,
    *,
    tenant_id: str,
    creator_id: str | None = None,
    source_type: str = "web",
    source_name: str | None = None,
    occurred_at: datetime | None = None,
    location: dict | None = None,
    payload: dict | None = None,
) -> HumanProofSession:
    session = HumanProofSession(
        session_id=f"HP-{uuid.uuid4().hex.upper()}",
        tenant_id=tenant_id,
        status="recording",
        schema_version=SCHEMA_VERSION,
        created_by=creator_id,
        started_at=_normalize_datetime(occurred_at),
    )
    db.add(session)
    db.flush()
    append_event(
        db,
        session=session,
        event_type="session_started",
        source_type=source_type,
        source_name=source_name,
        creator_id=creator_id,
        occurred_at=occurred_at,
        location=location,
        payload=payload or {},
        _allow_system_close=False,
    )
    db.commit()
    db.refresh(session)
    return session


def append_event(
    db: Session,
    *,
    session: HumanProofSession,
    event_type: str,
    source_type: str,
    source_name: str | None = None,
    creator_id: str | None = None,
    occurred_at: datetime | None = None,
    ai_disclosure: dict | None = None,
    location: dict | None = None,
    payload: dict | None = None,
    omni_id: str | None = None,
    _allow_system_close: bool = False,
) -> HumanProofEvent:
    if event_type not in ALLOWED_EVENT_TYPES:
        raise ValueError(f"Unsupported HumanProof event type: {event_type}")
    if session.status != "recording" and not (_allow_system_close and event_type == "session_closed"):
        raise ValueError("HumanProof session is closed")
    if event_type == "session_started" and session.events:
        raise ValueError("HumanProof session already started")
    if event_type == "session_closed" and not _allow_system_close:
        raise ValueError("Use the close-session operation")

    location = validate_location(location)
    payload = payload or {}

    target_omni_id = omni_id or session.omni_id
    if event_type == "asset_registered":
        target_omni_id = omni_id or payload.get("omni_id")
        if not target_omni_id:
            raise ValueError("asset_registered requires omni_id")
        asset = (
            db.query(Asset)
            .filter(Asset.omni_id == target_omni_id, Asset.tenant_id == session.tenant_id)
            .first()
        )
        if not asset:
            raise ValueError("Asset not found for this tenant")
        declared_sha = payload.get("sha256")
        if declared_sha and declared_sha != asset.sha256:
            raise ValueError("HumanProof asset fingerprint does not match registered asset")
        payload = {**payload, "omni_id": asset.omni_id, "sha256": asset.sha256}
        session.omni_id = asset.omni_id
        target_omni_id = asset.omni_id

    events = (
        db.query(HumanProofEvent)
        .filter(HumanProofEvent.session_id == session.session_id)
        .order_by(HumanProofEvent.sequence.asc())
        .all()
    )
    sequence = len(events) + 1
    previous_hash = events[-1].evidence_hash if events else None
    event_id = f"HPE-{uuid.uuid4().hex.upper()}"
    occurred = _normalize_datetime(occurred_at)
    recorded = _utcnow()
    event_hash = compute_event_hash(
        event_id=event_id,
        session_id=session.session_id,
        omni_id=target_omni_id,
        sequence=sequence,
        event_type=event_type,
        occurred_at=occurred,
        recorded_at=recorded,
        previous_event_hash=previous_hash,
        source_type=source_type,
        source_name=source_name,
        creator_id=creator_id,
        ai_disclosure=ai_disclosure,
        location=location,
        payload=payload,
        schema_version=SCHEMA_VERSION,
    )
    event = HumanProofEvent(
        event_id=event_id,
        session_id=session.session_id,
        tenant_id=session.tenant_id,
        omni_id=target_omni_id,
        sequence=sequence,
        event_type=event_type,
        occurred_at=occurred,
        recorded_at=recorded,
        evidence_hash=event_hash,
        previous_event_hash=previous_hash,
        source_type=source_type,
        source_name=source_name,
        creator_id=creator_id,
        ai_disclosure_json=_canonical_json(ai_disclosure) if ai_disclosure is not None else None,
        location_json=_canonical_json(location) if location is not None else None,
        payload_json=_canonical_json(payload),
        schema_version=SCHEMA_VERSION,
    )
    db.add(event)
    session.current_hash = event_hash
    db.flush()
    return event


def verify_session_chain(db: Session, session: HumanProofSession) -> dict:
    events = (
        db.query(HumanProofEvent)
        .filter(HumanProofEvent.session_id == session.session_id)
        .order_by(HumanProofEvent.sequence.asc())
        .all()
    )
    failures: list[dict] = []
    previous_hash = None
    expected_sequence = 1

    for event in events:
        if event.sequence != expected_sequence:
            failures.append({"event_id": event.event_id, "reason": "sequence_gap"})
        if event.previous_event_hash != previous_hash:
            failures.append({"event_id": event.event_id, "reason": "previous_hash_mismatch"})

        recalculated = compute_event_hash(
            event_id=event.event_id,
            session_id=event.session_id,
            omni_id=event.omni_id,
            sequence=event.sequence,
            event_type=event.event_type,
            occurred_at=event.occurred_at,
            recorded_at=event.recorded_at,
            previous_event_hash=event.previous_event_hash,
            source_type=event.source_type,
            source_name=event.source_name,
            creator_id=event.creator_id,
            ai_disclosure=_loads(event.ai_disclosure_json, None),
            location=_loads(event.location_json, None),
            payload=_loads(event.payload_json, {}),
            schema_version=event.schema_version,
        )
        if recalculated != event.evidence_hash:
            failures.append({"event_id": event.event_id, "reason": "evidence_hash_mismatch"})

        previous_hash = event.evidence_hash
        expected_sequence += 1

    if events and session.current_hash != events[-1].evidence_hash:
        failures.append({"event_id": events[-1].event_id, "reason": "session_head_mismatch"})

    return {
        "valid": not failures,
        "event_count": len(events),
        "head_hash": previous_hash,
        "failures": failures,
    }


def completion_check(events: list[HumanProofEvent], chain_valid: bool) -> tuple[bool, list[str]]:
    types = [event.event_type for event in events]
    missing: list[str] = []
    if not types or types[0] != "session_started":
        missing.append("session_started")
    if not any(t in types for t in {"source_captured", "work_saved", "work_exported"}):
        missing.append("creation_evidence")
    if "ai_tool_disclosed" not in types:
        missing.append("ai_disclosure")
    if "asset_registered" not in types:
        missing.append("asset_registered")
    if not chain_valid:
        missing.append("valid_evidence_chain")
    return not missing, missing


def close_session(
    db: Session,
    *,
    session: HumanProofSession,
    source_type: str = "web",
    source_name: str | None = None,
    creator_id: str | None = None,
    occurred_at: datetime | None = None,
) -> tuple[HumanProofSession, dict]:
    if session.status != "recording":
        raise ValueError("HumanProof session is already closed")

    preflight = verify_session_chain(db, session)
    current_events = (
        db.query(HumanProofEvent)
        .filter(HumanProofEvent.session_id == session.session_id)
        .order_by(HumanProofEvent.sequence.asc())
        .all()
    )
    eligible, missing = completion_check(current_events, preflight["valid"])

    append_event(
        db,
        session=session,
        event_type="session_closed",
        source_type=source_type,
        source_name=source_name,
        creator_id=creator_id,
        occurred_at=occurred_at,
        payload={"eligible_for_complete": eligible, "missing": missing},
        _allow_system_close=True,
    )
    final_chain = verify_session_chain(db, session)
    session.status = "complete" if eligible and final_chain["valid"] else "incomplete"
    if not final_chain["valid"]:
        session.status = "integrity_failed"
    session.closed_at = _normalize_datetime(occurred_at)
    db.commit()
    db.refresh(session)
    return session, {"chain": final_chain, "missing": missing}


def serialize_event(event: HumanProofEvent, *, public: bool = False) -> dict:
    location = _loads(event.location_json, None)
    if public and location and location.get("level") == "precise_private":
        location = {"level": "precise_private", "public_summary": "private"}
    return {
        "event_id": event.event_id,
        "session_id": event.session_id,
        "omni_id": event.omni_id,
        "sequence": event.sequence,
        "event_type": event.event_type,
        "occurred_at": event.occurred_at.isoformat() + "Z" if event.occurred_at else None,
        "recorded_at": event.recorded_at.isoformat() + "Z" if event.recorded_at else None,
        "evidence_hash": event.evidence_hash,
        "previous_event_hash": event.previous_event_hash,
        "source_type": event.source_type,
        "source_name": event.source_name,
        "creator_id": None if public else event.creator_id,
        "ai_disclosure": _loads(event.ai_disclosure_json, None),
        "location": location,
        "payload": _loads(event.payload_json, {}),
        "schema_version": event.schema_version,
    }


def serialize_session(db: Session, session: HumanProofSession, *, public: bool = False) -> dict:
    events = (
        db.query(HumanProofEvent)
        .filter(HumanProofEvent.session_id == session.session_id)
        .order_by(HumanProofEvent.sequence.asc())
        .all()
    )
    chain = verify_session_chain(db, session)
    return {
        "session_id": session.session_id,
        "omni_id": session.omni_id,
        "status": session.status,
        "schema_version": session.schema_version,
        "event_count": len(events),
        "chain_integrity": chain,
        "started_at": session.started_at.isoformat() + "Z" if session.started_at else None,
        "closed_at": session.closed_at.isoformat() + "Z" if session.closed_at else None,
        "events": [serialize_event(event, public=public) for event in events],
    }
