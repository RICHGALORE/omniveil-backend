import json
from datetime import datetime

from sqlalchemy.orm import Session

from app.db.humanproof_models import HumanProofSession
from app.db.humanproof_publication_models import HumanProofPublication
from app.services.humanproof import serialize_session
from app.services.humanproof_public import (
    PUBLIC_SESSION_STATUSES,
    get_public_humanproof_summary as build_public_humanproof_summary,
)


ALLOWED_PUBLIC_FIELDS = {
    "production_environment",
    "connected_production_hardware",
    "additional_production_apps",
    "source_omni_id",
    "transformation_statement",
}


def normalize_public_fields(values: list[str]) -> list[str]:
    normalized = sorted({value.strip() for value in values if value and value.strip()})
    unsupported = [value for value in normalized if value not in ALLOWED_PUBLIC_FIELDS]
    if unsupported:
        raise ValueError(f"Unsupported public HumanProof field: {unsupported[0]}")
    return normalized


def get_publication_fields(db: Session, session_id: str) -> list[str]:
    row = db.query(HumanProofPublication).filter(HumanProofPublication.session_id == session_id).first()
    if not row or not row.fields_json:
        return []
    try:
        values = json.loads(row.fields_json)
    except (TypeError, json.JSONDecodeError):
        return []
    if not isinstance(values, list):
        return []
    return [value for value in values if isinstance(value, str) and value in ALLOWED_PUBLIC_FIELDS]


def set_publication_fields(
    db: Session,
    *,
    session: HumanProofSession,
    fields: list[str],
) -> HumanProofPublication:
    normalized = normalize_public_fields(fields)
    row = db.query(HumanProofPublication).filter(HumanProofPublication.session_id == session.session_id).first()
    if row is None:
        row = HumanProofPublication(
            session_id=session.session_id,
            tenant_id=session.tenant_id,
            omni_id=session.omni_id or "",
            fields_json=json.dumps(normalized, separators=(",", ":")),
        )
        db.add(row)
    else:
        row.tenant_id = session.tenant_id
        row.omni_id = session.omni_id or row.omni_id
        row.fields_json = json.dumps(normalized, separators=(",", ":"))
        row.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(row)
    return row


def publication_settings(db: Session, session: HumanProofSession) -> dict:
    fields = get_publication_fields(db, session.session_id)
    return {
        "session_id": session.session_id,
        "omni_id": session.omni_id,
        "published_fields": fields,
        "available_fields": sorted(ALLOWED_PUBLIC_FIELDS),
        "evidence_chain_mutated": False,
    }


def _derive_public_evidence_summary(serialized: dict, published_fields: set[str]) -> dict:
    events = serialized.get("events") or []
    started = next((event for event in events if event.get("event_type") == "session_started"), None)
    started_payload = (started or {}).get("payload") or {}

    allowed_workflows = {
        "HumanProof Studio",
        "HumanProof DAW AutoDetect v1",
        "HumanProof DAW Manual Setup",
        "Human Transformation v1",
    }
    workflow_value = started_payload.get("workflow")
    workflow = workflow_value if workflow_value in allowed_workflows else None

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
                "source_omni_id": (
                    payload.get("source_omni_id") if "source_omni_id" in published_fields else None
                ),
                "history_preserved": payload.get("history_mutated") is False,
            }

        if checkpoint == "human_transformation_declared":
            declared = payload.get("transformations") or []
            if isinstance(declared, list):
                transformations = [value for value in declared if isinstance(value, str)]
            if "transformation_statement" in published_fields and isinstance(payload.get("statement"), str):
                transformation_statement = payload.get("statement")

        if event.get("event_type") == "ai_tool_disclosed":
            value = payload.get("final_provenance_disclosure")
            if isinstance(value, str):
                final_provenance_disclosure = value

    return {
        "workflow": workflow,
        "published_fields": sorted(published_fields),
        "production_environment": (
            production_environment if "production_environment" in published_fields else None
        ),
        "connected_production_hardware": (
            connected_hardware if "connected_production_hardware" in published_fields else []
        ),
        "additional_production_apps": (
            additional_apps if "additional_production_apps" in published_fields else []
        ),
        "automatic_project_detected": any(
            (event.get("payload") or {}).get("checkpoint") == "automatic_project_detected"
            for event in events
        ),
        "automatic_revisions": automatic_revisions,
        "automatic_exports": automatic_exports,
        "contributor_declarations": contributor_declarations,
        "human_transformation": {
            "verified": bool(source_lineage and transformations),
            "source_lineage": source_lineage,
            "transformations": transformations,
            "statement": transformation_statement,
            "final_provenance_disclosure": final_provenance_disclosure,
        },
    }


def build_public_record(db: Session, omni_id: str) -> dict | None:
    compact_summary = build_public_humanproof_summary(db, omni_id)
    if compact_summary is None:
        return None

    session = (
        db.query(HumanProofSession)
        .filter(
            HumanProofSession.omni_id == omni_id,
            HumanProofSession.status.in_(PUBLIC_SESSION_STATUSES),
        )
        .order_by(HumanProofSession.closed_at.desc(), HumanProofSession.created_at.desc())
        .first()
    )
    if session is None:
        return None

    published_fields = set(get_publication_fields(db, session.session_id))
    summary = serialize_session(db, session, public=True)
    summary["privacy_mode"] = compact_summary["privacy_mode"]
    summary["evidence_summary"] = _derive_public_evidence_summary(summary, published_fields)

    for event in summary["events"]:
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
