import uuid

from fastapi.testclient import TestClient

import main
from app.core.tenant import hash_api_key
from app.db.humanproof_models import HumanProofEvent, HumanProofSession
from app.db.models import Asset, Client
from app.db.session import SessionLocal


RAW_KEY = "ov_live_humanproof_test_key"
OTHER_KEY = "ov_live_humanproof_other_key"
TENANT_ID = "humanproof-test-tenant"
OTHER_TENANT_ID = "humanproof-other-tenant"


def _ensure_client(raw_key: str, tenant_id: str, email: str) -> None:
    db = SessionLocal()
    try:
        key_hash = hash_api_key(raw_key)
        if not db.query(Client).filter(Client.api_key_hash == key_hash).first():
            db.add(
                Client(
                    id=str(uuid.uuid4()),
                    tenant_id=tenant_id,
                    company_name=f"{tenant_id} Test",
                    email=email,
                    status="approved",
                    plan="creator",
                    api_key_hash=key_hash,
                )
            )
            db.commit()
    finally:
        db.close()


def _create_asset(tenant_id: str) -> Asset:
    db = SessionLocal()
    try:
        token = uuid.uuid4().hex
        asset = Asset(
            omni_id=f"OV-HP-{token[:16].upper()}",
            asset_id=f"asset-{token}",
            tenant_id=tenant_id,
            filename="humanproof-test.wav",
            file_type="audio/wav",
            original_path=f"/tmp/{token}.wav",
            sha256=(token * 2)[:64],
            blake3=(token[::-1] * 2)[:64],
            trust_score=0.5,
            content_label="unverified",
        )
        db.add(asset)
        db.commit()
        db.refresh(asset)
        db.expunge(asset)
        return asset
    finally:
        db.close()


def _start(client: TestClient, raw_key: str, location: dict | None = None) -> dict:
    response = client.post(
        "/api/v1/humanproof/sessions",
        headers={"X-API-Key": raw_key},
        json={
            "creator_id": "creator-1",
            "source_type": "daw",
            "source_name": "Logic Pro",
            "location": location,
            "payload": {"project_name": "HumanProof Test"},
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _event(client: TestClient, raw_key: str, session_id: str, event_type: str, **extra) -> dict:
    body = {
        "event_type": event_type,
        "source_type": "daw",
        "source_name": "Logic Pro",
        "creator_id": "creator-1",
        "payload": extra.pop("payload", {}),
        **extra,
    }
    response = client.post(
        f"/api/v1/humanproof/sessions/{session_id}/events",
        headers={"X-API-Key": raw_key},
        json=body,
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_humanproof_complete_session_binds_asset_and_verifies_chain():
    with TestClient(main.app, raise_server_exceptions=False) as client:
        _ensure_client(RAW_KEY, TENANT_ID, "humanproof-owner@example.com")
        asset = _create_asset(TENANT_ID)
        started = _start(client, RAW_KEY)
        session_id = started["session_id"]

        _event(
            client,
            RAW_KEY,
            session_id,
            "source_captured",
            payload={"source_file": "session.logicx"},
        )
        _event(
            client,
            RAW_KEY,
            session_id,
            "ai_tool_disclosed",
            ai_disclosure={"used": False, "tools": [], "role": None},
            payload={"attestation": "No AI tools used in this workflow"},
        )
        registered = _event(
            client,
            RAW_KEY,
            session_id,
            "asset_registered",
            omni_id=asset.omni_id,
            payload={"sha256": asset.sha256},
        )
        assert registered["omni_id"] == asset.omni_id

        closed = client.post(
            f"/api/v1/humanproof/sessions/{session_id}/close",
            headers={"X-API-Key": RAW_KEY},
            json={"source_type": "daw", "source_name": "Logic Pro"},
        )
        assert closed.status_code == 200, closed.text
        body = closed.json()
        assert body["status"] == "complete"
        assert body["omni_id"] == asset.omni_id
        assert body["chain_integrity"]["valid"] is True
        assert body["event_count"] == 5

        verify = client.get(
            f"/api/v1/humanproof/sessions/{session_id}/verify",
            headers={"X-API-Key": RAW_KEY},
        )
        assert verify.status_code == 200
        assert verify.json()["chain_integrity"]["valid"] is True


def test_humanproof_tenant_isolation_hides_sessions_and_asset_binding():
    with TestClient(main.app, raise_server_exceptions=False) as client:
        _ensure_client(RAW_KEY, TENANT_ID, "humanproof-owner@example.com")
        _ensure_client(OTHER_KEY, OTHER_TENANT_ID, "humanproof-other@example.com")
        foreign_asset = _create_asset(OTHER_TENANT_ID)
        started = _start(client, RAW_KEY)
        session_id = started["session_id"]

        hidden = client.get(
            f"/api/v1/humanproof/sessions/{session_id}",
            headers={"X-API-Key": OTHER_KEY},
        )
        assert hidden.status_code == 404

        bind = client.post(
            f"/api/v1/humanproof/sessions/{session_id}/events",
            headers={"X-API-Key": RAW_KEY},
            json={
                "event_type": "asset_registered",
                "source_type": "web",
                "omni_id": foreign_asset.omni_id,
                "payload": {"sha256": foreign_asset.sha256},
            },
        )
        assert bind.status_code == 400
        assert "Asset not found for this tenant" in bind.json()["detail"]


def test_humanproof_detects_database_tampering():
    with TestClient(main.app, raise_server_exceptions=False) as client:
        _ensure_client(RAW_KEY, TENANT_ID, "humanproof-owner@example.com")
        started = _start(client, RAW_KEY)
        session_id = started["session_id"]
        _event(client, RAW_KEY, session_id, "work_saved", payload={"version": 1})

        db = SessionLocal()
        try:
            event = (
                db.query(HumanProofEvent)
                .filter(
                    HumanProofEvent.session_id == session_id,
                    HumanProofEvent.event_type == "work_saved",
                )
                .one()
            )
            event.payload_json = '{"version":999}'
            db.commit()
        finally:
            db.close()

        verify = client.get(
            f"/api/v1/humanproof/sessions/{session_id}/verify",
            headers={"X-API-Key": RAW_KEY},
        )
        assert verify.status_code == 200
        result = verify.json()["chain_integrity"]
        assert result["valid"] is False
        assert any(failure["reason"] == "evidence_hash_mismatch" for failure in result["failures"])


def test_humanproof_rejects_wrong_registered_fingerprint():
    with TestClient(main.app, raise_server_exceptions=False) as client:
        _ensure_client(RAW_KEY, TENANT_ID, "humanproof-owner@example.com")
        asset = _create_asset(TENANT_ID)
        session_id = _start(client, RAW_KEY)["session_id"]

        response = client.post(
            f"/api/v1/humanproof/sessions/{session_id}/events",
            headers={"X-API-Key": RAW_KEY},
            json={
                "event_type": "asset_registered",
                "source_type": "web",
                "omni_id": asset.omni_id,
                "payload": {"sha256": "0" * 64},
            },
        )
        assert response.status_code == 400
        assert "fingerprint does not match" in response.json()["detail"]


def test_public_humanproof_masks_precise_private_location():
    with TestClient(main.app, raise_server_exceptions=False) as client:
        _ensure_client(RAW_KEY, TENANT_ID, "humanproof-owner@example.com")
        asset = _create_asset(TENANT_ID)
        session_id = _start(
            client,
            RAW_KEY,
            location={"level": "precise_private", "latitude": 36.1716, "longitude": -115.1391},
        )["session_id"]
        _event(client, RAW_KEY, session_id, "work_exported", payload={"format": "wav"})
        _event(
            client,
            RAW_KEY,
            session_id,
            "ai_tool_disclosed",
            ai_disclosure={"used": False, "tools": []},
        )
        _event(
            client,
            RAW_KEY,
            session_id,
            "asset_registered",
            omni_id=asset.omni_id,
            payload={"sha256": asset.sha256},
        )
        close = client.post(
            f"/api/v1/humanproof/sessions/{session_id}/close",
            headers={"X-API-Key": RAW_KEY},
            json={},
        )
        assert close.status_code == 200
        assert close.json()["status"] == "complete"

        public = client.get(f"/api/v1/humanproof/assets/{asset.omni_id}/public")
        assert public.status_code == 200, public.text
        first_location = public.json()["events"][0]["location"]
        assert first_location == {"level": "precise_private", "public_summary": "private"}
        assert "latitude" not in str(public.json())
        assert "longitude" not in str(public.json())
