import io
import json
import uuid

from fastapi.testclient import TestClient
from PIL import Image

import main
from app.core.tenant import hash_api_key
from app.db.models import Client
from app.db.session import SessionLocal


def _identity(prefix: str):
    token = uuid.uuid4().hex
    return (
        f"ov_live_{prefix}_{token}",
        f"{prefix}-{token}",
        f"{prefix}-{token}@example.com",
    )


def _ensure_client(raw_key: str, tenant_id: str, email: str) -> None:
    db = SessionLocal()
    try:
        db.add(
            Client(
                id=str(uuid.uuid4()),
                tenant_id=tenant_id,
                company_name="HumanProof Publication Test",
                email=email,
                status="approved",
                plan="creator",
                api_key_hash=hash_api_key(raw_key),
            )
        )
        db.commit()
    finally:
        db.close()


def _png_bytes() -> bytes:
    image = Image.new("RGB", (24, 24), tuple(uuid.uuid4().bytes[:3]))
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    return buffer.getvalue()


def _upload(client: TestClient, raw_key: str) -> dict:
    response = client.post(
        "/api/v1/upload",
        headers={"X-API-Key": raw_key},
        files={"file": ("publication-test.png", _png_bytes(), "image/png")},
        data={
            "provenance_json": json.dumps({"creator_name": "Publication Tester"}),
            "options_json": "{}",
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


def _complete_humanproof(client: TestClient, raw_key: str, omni_id: str) -> dict:
    headers = {"X-API-Key": raw_key}
    started = client.post(
        "/api/v1/humanproof/sessions",
        headers=headers,
        json={
            "creator_id": "publication-tester",
            "source_type": "daw",
            "source_name": "Private Logic Name",
            "payload": {
                "workflow": "HumanProof DAW AutoDetect v1",
                "daw_name": "Logic Pro",
                "privacy_mode": "public",
                "private_project_name": "Never Publish This Project",
            },
        },
    )
    assert started.status_code == 201, started.text
    session_id = started.json()["session_id"]

    source = client.post(
        f"/api/v1/humanproof/sessions/{session_id}/events",
        headers=headers,
        json={
            "event_type": "source_captured",
            "source_type": "daw",
            "source_name": "Private Logic Name",
            "payload": {
                "checkpoint": "automatic_project_detected",
                "connected_production_hardware": [
                    {
                        "name": "MPC Key 61",
                        "category": "production_workstation",
                        "serial": "DO-NOT-PUBLISH-SERIAL",
                    }
                ],
                "process_only_environments": ["Serato DJ Pro"],
                "private_source_path": "/Users/private/secret.logicx",
            },
        },
    )
    assert source.status_code == 201, source.text

    disclosure = client.post(
        f"/api/v1/humanproof/sessions/{session_id}/events",
        headers=headers,
        json={
            "event_type": "ai_tool_disclosed",
            "source_type": "web",
            "ai_disclosure": {"used": False, "tools": []},
            "payload": {"declaration": "human"},
        },
    )
    assert disclosure.status_code == 201, disclosure.text

    registered = client.post(
        f"/api/v1/humanproof/sessions/{session_id}/events",
        headers=headers,
        json={
            "event_type": "asset_registered",
            "source_type": "registry",
            "omni_id": omni_id,
            "payload": {"omni_id": omni_id},
        },
    )
    assert registered.status_code == 201, registered.text

    closed = client.post(
        f"/api/v1/humanproof/sessions/{session_id}/close",
        headers=headers,
        json={"source_type": "web"},
    )
    assert closed.status_code == 200, closed.text
    assert closed.json()["status"] == "complete"
    return closed.json()


def test_publication_is_opt_in_and_exposes_only_selected_safe_values():
    raw_key, tenant_id, email = _identity("hp-publish")
    with TestClient(main.app, raise_server_exceptions=False) as client:
        _ensure_client(raw_key, tenant_id, email)
        uploaded = _upload(client, raw_key)
        session = _complete_humanproof(client, raw_key, uploaded["omni_id"])

        public_before = client.get(
            f"/api/v1/humanproof-publication/assets/{uploaded['omni_id']}/public"
        )
        assert public_before.status_code == 200, public_before.text
        before = public_before.json()["evidence_summary"]
        assert before["production_environment"] is None
        assert before["connected_production_hardware"] == []
        assert before["additional_production_apps"] == []
        assert before["published_fields"] == []

        updated = client.put(
            f"/api/v1/humanproof-publication/assets/{uploaded['omni_id']}",
            headers={"X-API-Key": raw_key},
            json={"fields": ["production_environment", "connected_production_hardware"]},
        )
        assert updated.status_code == 200, updated.text
        assert updated.json()["session_id"] == session["session_id"]
        assert updated.json()["evidence_chain_mutated"] is False

        public_after = client.get(
            f"/api/v1/humanproof-publication/assets/{uploaded['omni_id']}/public"
        )
        assert public_after.status_code == 200, public_after.text
        body = public_after.json()
        evidence = body["evidence_summary"]
        assert evidence["production_environment"] == "Logic Pro"
        assert evidence["connected_production_hardware"] == [
            {"name": "MPC Key 61", "category": "production_workstation"}
        ]
        assert evidence["additional_production_apps"] == []
        assert evidence["published_fields"] == [
            "connected_production_hardware",
            "production_environment",
        ]

        serialized = json.dumps(body)
        assert "DO-NOT-PUBLISH-SERIAL" not in serialized
        assert "Never Publish This Project" not in serialized
        assert "/Users/private/secret.logicx" not in serialized
        assert "Serato DJ Pro" not in serialized
        for event in body["events"]:
            assert "payload" not in event
            assert "source_name" not in event
            assert "creator_id" not in event


def test_publication_rejects_unknown_fields_and_enforces_tenant_isolation():
    raw_key, tenant_id, email = _identity("hp-owner")
    other_key, other_tenant_id, other_email = _identity("hp-other")
    with TestClient(main.app, raise_server_exceptions=False) as client:
        _ensure_client(raw_key, tenant_id, email)
        _ensure_client(other_key, other_tenant_id, other_email)
        uploaded = _upload(client, raw_key)
        _complete_humanproof(client, raw_key, uploaded["omni_id"])

        invalid = client.put(
            f"/api/v1/humanproof-publication/assets/{uploaded['omni_id']}",
            headers={"X-API-Key": raw_key},
            json={"fields": ["private_source_path"]},
        )
        assert invalid.status_code == 400

        cross_tenant = client.put(
            f"/api/v1/humanproof-publication/assets/{uploaded['omni_id']}",
            headers={"X-API-Key": other_key},
            json={"fields": ["production_environment"]},
        )
        assert cross_tenant.status_code == 404
