import uuid

from fastapi.testclient import TestClient

import main
from app.core.tenant import hash_api_key
from app.db.models import Client
from app.db.session import SessionLocal


def _identity():
    token = uuid.uuid4().hex
    return (
        f"ov_live_hp_contributor_{token}",
        f"hp-contributor-{token}",
        f"hp-contributor-{token}@example.com",
    )


def _ensure_client(raw_key: str, tenant_id: str, email: str) -> None:
    db = SessionLocal()
    try:
        db.add(
            Client(
                id=str(uuid.uuid4()),
                tenant_id=tenant_id,
                company_name="HumanProof Contributor Semantics Test",
                email=email,
                status="approved",
                plan="creator",
                api_key_hash=hash_api_key(raw_key),
            )
        )
        db.commit()
    finally:
        db.close()


def test_primary_creator_declaration_and_contributor_attestation_are_distinct_events():
    raw_key, tenant_id, email = _identity()
    headers = {"X-API-Key": raw_key}

    with TestClient(main.app, raise_server_exceptions=False) as client:
        _ensure_client(raw_key, tenant_id, email)
        started = client.post(
            "/api/v1/humanproof/sessions",
            headers=headers,
            json={
                "creator_id": "primary-creator",
                "source_type": "web",
                "source_name": "HumanProof Studio",
                "payload": {"privacy_mode": "proof"},
            },
        )
        assert started.status_code == 201, started.text
        session_id = started.json()["session_id"]

        declared = client.post(
            f"/api/v1/humanproof/sessions/{session_id}/events",
            headers=headers,
            json={
                "event_type": "contributor_declared",
                "source_type": "web",
                "source_name": "HumanProof Studio",
                "creator_id": "primary-creator",
                "payload": {
                    "contributor_name": "Collaborator One",
                    "role": "Producer",
                    "declaration_source": "primary_creator",
                    "attestation_status": "declared_not_self_attested",
                },
            },
        )
        assert declared.status_code == 201, declared.text
        declared_event = declared.json()["events"][-1]
        assert declared_event["event_type"] == "contributor_declared"
        assert declared_event["payload"]["declaration_source"] == "primary_creator"
        assert declared_event["payload"]["attestation_status"] == "declared_not_self_attested"

        attested = client.post(
            f"/api/v1/humanproof/sessions/{session_id}/events",
            headers=headers,
            json={
                "event_type": "contributor_attested",
                "source_type": "web",
                "source_name": "HumanProof Contributor Attestation",
                "creator_id": "collaborator-one",
                "payload": {
                    "contributor_name": "Collaborator One",
                    "role": "Producer",
                    "attestation_status": "self_attested",
                },
            },
        )
        assert attested.status_code == 201, attested.text
        attested_event = attested.json()["events"][-1]
        assert attested_event["event_type"] == "contributor_attested"
        assert attested_event["payload"]["attestation_status"] == "self_attested"

        verified = client.get(
            f"/api/v1/humanproof/sessions/{session_id}/verify",
            headers=headers,
        )
        assert verified.status_code == 200, verified.text
        assert verified.json()["chain_integrity"]["valid"] is True
        assert verified.json()["chain_integrity"]["event_count"] == 3
