import uuid

from fastapi.testclient import TestClient

import main
from app.core.tenant import hash_api_key
from app.db.models import Asset, Client
from app.db.session import SessionLocal


RAW_KEY = "ov_live_human_transformation_test_key"
OTHER_KEY = "ov_live_human_transformation_other_key"
TENANT_ID = "human-transformation-test-tenant"
OTHER_TENANT_ID = "human-transformation-other-tenant"


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


def _create_source_asset(tenant_id: str) -> Asset:
    db = SessionLocal()
    try:
        token = uuid.uuid4().hex
        asset = Asset(
            omni_id=f"OV-HT-{token[:16].upper()}",
            asset_id=f"asset-{token}",
            tenant_id=tenant_id,
            filename="ai-source.wav",
            file_type="audio/wav",
            original_path=f"/tmp/{token}.wav",
            sha256=(token * 2)[:64],
            blake3=(token[::-1] * 2)[:64],
            trust_score=0.42,
            content_label="ai_generated",
            ai_disclosure="ai_generated",
            ai_detection_score=0.91,
        )
        db.add(asset)
        db.commit()
        db.refresh(asset)
        db.expunge(asset)
        return asset
    finally:
        db.close()


def test_human_transformation_snapshots_source_ai_history_without_mutation():
    with TestClient(main.app, raise_server_exceptions=False) as client:
        _ensure_client(RAW_KEY, TENANT_ID, "human-transform@example.com")
        source = _create_source_asset(TENANT_ID)

        response = client.post(
            "/api/v1/human-transformation/sessions",
            headers={"X-API-Key": RAW_KEY},
            json={
                "source_omni_id": source.omni_id,
                "creator_id": "creator-1",
                "project_title": "Humanized Version",
                "production_environment": "Logic Pro + MPC Key 61",
                "privacy_mode": "proof",
            },
        )
        assert response.status_code == 201, response.text
        body = response.json()
        assert body["status"] == "recording"
        assert body["event_count"] == 2

        source_event = body["events"][1]
        assert source_event["event_type"] == "source_captured"
        payload = source_event["payload"]
        assert payload["checkpoint"] == "source_asset_linked"
        assert payload["source_omni_id"] == source.omni_id
        assert payload["source_sha256"] == source.sha256
        assert payload["source_ai_disclosure"] == "ai_generated"
        assert payload["source_ai_detection_score"] == 0.91
        assert payload["history_mutated"] is False

        db = SessionLocal()
        try:
            unchanged = db.query(Asset).filter(Asset.omni_id == source.omni_id).one()
            assert unchanged.ai_disclosure == "ai_generated"
            assert unchanged.ai_detection_score == 0.91
            assert unchanged.sha256 == source.sha256
        finally:
            db.close()


def test_human_transformation_records_specific_creator_work_without_erasing_source():
    with TestClient(main.app, raise_server_exceptions=False) as client:
        _ensure_client(RAW_KEY, TENANT_ID, "human-transform@example.com")
        source = _create_source_asset(TENANT_ID)
        started = client.post(
            "/api/v1/human-transformation/sessions",
            headers={"X-API-Key": RAW_KEY},
            json={"source_omni_id": source.omni_id, "creator_id": "creator-1"},
        )
        assert started.status_code == 201, started.text
        session_id = started.json()["session_id"]

        declared = client.post(
            f"/api/v1/human-transformation/sessions/{session_id}/declare",
            headers={"X-API-Key": RAW_KEY},
            json={
                "transformations": ["rearranged", "vocals_replaced", "mix_rebuilt"],
                "statement": "Rebuilt the arrangement, replaced the vocal performance, and remixed the record.",
                "production_environment": "Logic Pro",
            },
        )
        assert declared.status_code == 200, declared.text
        event = declared.json()["events"][-1]
        assert event["event_type"] == "work_saved"
        assert event["payload"]["checkpoint"] == "human_transformation_declared"
        assert event["payload"]["transformations"] == ["rearranged", "vocals_replaced", "mix_rebuilt"]
        assert event["payload"]["does_not_erase_source_ai_history"] is True


def test_human_transformation_cannot_link_another_tenants_source():
    with TestClient(main.app, raise_server_exceptions=False) as client:
        _ensure_client(RAW_KEY, TENANT_ID, "human-transform@example.com")
        _ensure_client(OTHER_KEY, OTHER_TENANT_ID, "human-transform-other@example.com")
        foreign_source = _create_source_asset(OTHER_TENANT_ID)

        response = client.post(
            "/api/v1/human-transformation/sessions",
            headers={"X-API-Key": RAW_KEY},
            json={"source_omni_id": foreign_source.omni_id},
        )
        assert response.status_code == 404
        assert "Source asset not found" in response.json()["detail"]
