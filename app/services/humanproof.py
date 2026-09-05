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
    "contributor_declared",
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


def _validate_location(location: dict | None) -> dict | None:
    if location is None:
        return None
    if not isinstance(location, dict):
        raise ValueError("location must be an object")
    level = location.get("level", "none")
    if level not in ALLOWED_LOCATION_LEVELS:
        raise ValueError("Unsupported HumanProof location level")
    normalized = {"level": level}
    if level == "coarse":
        public_summary = location.get("public_summary")
        if public_summary:
            normalized["public_summary"] = str(public_summary)
    elif level == "precise_private":
        latitude = location.get("latitude")
        longitude = location.get("longitude")
        if latitude is not None:
            normalized["latitude"] = float(latitude)
        if longitude is not None:
            normalized["longitude"] = float(longitude)
        public_summary = location.get("public_summary")
        if public_summary:
            normalized["public_summary"] = str(public_summary)
    return normalized


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
    commit: bool = False,
) -> HumanProofEvent:
    if event_type not in ALLOWED_EVENT_TYPES:
        raise ValueError("Unsupported HumanProof event type")
    if session.status != "recording" and event_type != "session_closed":
        raise ValueError("HumanProof session is not recording")

    if event_type == "asset_registered":
        if not omni_id:
            raise ValueError("asset_registered requires omni_id")
        asset = (
            db.query(Asset)
            .filter(
                Asset.omni_id == omni_id,
                Asset.tenant_id == session.tenant_id,
            )
            .first()
        )
        if not asset:
            raise ValueError("Asset not found for this tenant")
        if session.omni_id and session.omni_id != omni_id:
            raise ValueError("HumanProof session is already bound to another asset")
        session.omni_id = omni_id

    occurred = _normalize_datetime(occurred_at)
    recorded = _utcnow()
    location_value = _validate_location(location)
    payload_value = payload or {}

    previous = (
        db.query(HumanProofEvent)
        .filter(HumanProofEvent.session_id == session.session_id)
        .order_by(HumanProofEvent.sequence.desc())
        .first()
    )
    sequence = (previous.sequence + 1) if previous else 1
    previous_hash = previous.evidence_hash if previous else None
    event_id = str(uuid.uuid4())

    evidence = _event_evidence_dict(
        event_id=event_id,
        session_id=session.session_id,
        omni_id=omni_id,
        sequence=sequence,
        event_type=event_type,
        occurred_at=occurred,
        recorded_at=recorded,
        previous_event_hash=previous_hash,
        source_type=source_type,
        source_name=source_name,
        creator_id=creator_id,
        ai_disclosure=ai_disclosure,
        location=location_value,
        payload=payload_value,
        schema_version=SCHEMA_VERSION,
    )
    event = HumanProofEvent(
        event_id=event_id,
        session_id=session.session_id,
        omni_id=omni_id,
        sequence=sequence,
        event_type=event_type,
        occurred_at=occurred,
        recorded_at=recorded,
        evidence_hash=hashlib.sha256(_canonical_json(evidence).encode("utf-8")).hexdigest(),
        previous_event_hash=previous_hash,
        source_type=source_type,
        source_name=source_name,
        creator_id=creator_id,
        ai_disclosure_json=_canonical_json(ai_disclosure) if ai_disclosure is not None else None,
        location_json=_canonical_json(location_value) if location_value is not None else None,
        payload_json=_canonical_json(payload_value),
        schema_version=SCHEMA_VERSION,
    )
    db.add(event)
    db.add(session)
    if commit:
        db.commit()
        db.refresh(event)
    else:
        db.flush()
    return event


def create_session(
    db: Session,
    *,
    tenant_id: str,
    creator_id: str | None,
    source_type: str,
    source_name: str | None = None,
    occurred_at: datetime | None = None,
    location: dict | None = None,
    payload: dict | None = None,
) -> HumanProofSession:
    session = HumanProofSession(
        session_id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        status="recording",
        schema_version=SCHEMA_VERSION,
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
    )
    db.commit()
    db.refresh(session)
    return session


def verify_session_chain(db: Session, session: HumanProofSession) -> dict:
    events = (
        db.query(HumanProofEvent)
        .filter(HumanProofEvent.session_id == session.session_id)
        .order_by(HumanProofEvent.sequence.asc())
        .all()
    )
    previous_hash = None
    failures = []
    for expected_sequence, event in enumerate(events, start=1):
        if event.sequence != expected_sequence:
            failures.append({"event_id": event.event_id, "reason": "sequence_gap"})
        if event.previous_event_hash != previous_hash:
            failures.append({"event_id": event.event_id, "reason": "previous_hash_mismatch"})

        expected_hash = compute_event_hash(
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
        if event.evidence_hash != expected_hash:
            failures.append({"event_id": event.event_id, "reason": "evidence_hash_mismatch"})
        previous_hash = event.evidence_hash

    return {
        "valid": not failures,
        "event_count": len(events),
        "head_hash": previous_hash,
        "failures": failures,
    }


def _serialize_event(event: HumanProofEvent, *, public: bool = False) -> dict:
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
        "source_name": None if public else event.source_name,
        "creator_id": None if public else event.creator_id,
        "ai_disclosure": _loads(event.ai_disclosure_json, None),
        "location": location,
        "payload": {} if public else _loads(event.payload_json, {}),
        "schema_version": event.schema_version,
    }


def serialize_session(db: Session, session: HumanProofSession, *, public: bool = False) -> dict:
    events = (
        db.query(HumanProofEvent)
        .filter(HumanProofEvent.session_id == session.session_id)
        .order_by(HumanProofEvent.sequence.asc())
        .all()
    )
    return {
        "session_id": session.session_id,
        "omni_id": session.omni_id,
        "status": session.status,
        "schema_version": session.schema_version,
        "started_at": session.started_at.isoformat() + "Z" if session.started_at else None,
        "closed_at": session.closed_at.isoformat() + "Z" if session.closed_at else None,
        "event_count": len(events),
        "chain_integrity": verify_session_chain(db, session),
        "events": [_serialize_event(event, public=public) for event in events],
    }


def _completion_state(db: Session, session: HumanProofSession) -> dict:
    events = (
        db.query(HumanProofEvent.event_type)
        .filter(HumanProofEvent.session_id == session.session_id)
        .all()
    )
    event_types = {event_type for (event_type,) in events}
    has_work = bool({"source_captured", "work_saved", "work_exported"} & event_types)
    missing = []
    if not has_work:
        missing.append("creation_evidence")
    if "ai_tool_disclosed" not in event_types:
        missing.append("ai_disclosure")
    if "asset_registered" not in event_types or not session.omni_id:
        missing.append("asset_binding")
    return {"complete": not missing, "missing": missing}


def close_session(
    db: Session,
    *,
    session: HumanProofSession,
    source_type: str,
    source_name: str | None = None,
    creator_id: str | None = None,
    occurred_at: datetime | None = None,
) -> tuple[HumanProofSession, dict]:
    if session.status != "recording":
        raise ValueError("HumanProof session is already closed")

    completion = _completion_state(db, session)
    append_event(
        db,
        session=session,
        event_type="session_closed",
        source_type=source_type,
        source_name=source_name,
        creator_id=creator_id,
        occurred_at=occurred_at,
        payload={"completion": completion},
    )
    chain = verify_session_chain(db, session)
    session.status = (
        "complete"
        if completion["complete"] and chain["valid"]
        else "integrity_failed"
        if not chain["valid"]
        else "incomplete"
    )
    session.closed_at = _utcnow()
    db.add(session)
    db.commit()
    db.refresh(session)
    return session, {"completion": completion, "chain": chain}
