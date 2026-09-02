import json

from sqlalchemy.orm import Session

from app.db.humanproof_models import HumanProofEvent, HumanProofSession
from app.services.humanproof import verify_session_chain


PUBLIC_SESSION_STATUSES = ("complete", "incomplete", "integrity_failed")


def _loads(value: str | None, default):
    if not value:
        return default
    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return default


def _iso(value):
    return value.isoformat() + "Z" if value else None


def _safe_location(events: list[HumanProofEvent]) -> dict | None:
    for event in events:
        location = _loads(event.location_json, None)
        if not isinstance(location, dict):
            continue
        level = location.get("level")
        if level == "precise_private":
            return {"level": "precise_private", "public_summary": "private"}
        if level == "coarse":
            public_summary = location.get("public_summary")
            if public_summary:
                return {"level": "coarse", "public_summary": str(public_summary)}
            return {"level": "coarse"}
    return None


def _ai_summary(events: list[HumanProofEvent]) -> dict | None:
    for event in reversed(events):
        if event.event_type != "ai_tool_disclosed":
            continue
        disclosure = _loads(event.ai_disclosure_json, None)
        if not isinstance(disclosure, dict) or not isinstance(disclosure.get("used"), bool):
            return None
        tools = disclosure.get("tools")
        if not isinstance(tools, list):
            tools = []
        return {
            "used": disclosure["used"],
            "tools": [str(tool) for tool in tools if tool],
            "role": disclosure.get("role"),
        }
    return None


def get_public_humanproof_summary(db: Session, omni_id: str) -> dict | None:
    """Return the public-safe HumanProof state for an asset.

    This intentionally exposes no raw workflow payloads, creator identifiers,
    source names, precise coordinates, private evidence, or event hashes.
    """
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
        return None

    events = (
        db.query(HumanProofEvent)
        .filter(HumanProofEvent.session_id == session.session_id)
        .order_by(HumanProofEvent.sequence.asc())
        .all()
    )
    chain = verify_session_chain(db, session)

    return {
        "status": session.status,
        "event_count": len(events),
        "chain_integrity": {
            "valid": bool(chain.get("valid")),
            "event_count": int(chain.get("event_count", len(events))),
        },
        "started_at": _iso(session.started_at),
        "closed_at": _iso(session.closed_at),
        "ai_disclosure": _ai_summary(events),
        "location": _safe_location(events),
        "asset_bound": session.omni_id == omni_id,
    }
