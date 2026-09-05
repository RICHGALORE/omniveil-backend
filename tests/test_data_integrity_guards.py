import io
import json
import uuid

from fastapi.testclient import TestClient
from PIL import Image

import main
from app.api.v1.endpoints.ingest import _normalize_ai_disclosure
from app.core.tenant import hash_api_key
from app.db.models import Client
from app.db.session import SessionLocal
from app.services.copyright_readiness import AuthorshipSignals, compute_copyright_readiness


RAW_KEY = "ov_data_integrity_guard_key"
TENANT_ID = "data-integrity-guard-tenant"


def _ensure_client() -> None:
    db = SessionLocal()
    try:
        key_hash = hash_api_key(RAW_KEY)
        if not db.query(Client).filter(Client.api_key_hash == key_hash).first():
            db.add(Client(
                id=str(uuid.uuid4()),
                tenant_id=TENANT_ID,
                company_name="Data Integrity Guard Test",
                email="data-integrity-guard@example.com",
                status="approved",
                plan="creator",
                api_key_hash=key_hash,
            ))
            db.commit()
    finally:
        db.close()


def _png_bytes() -> bytes:
    image = Image.new("RGB", (20, 20), tuple(uuid.uuid4().bytes[:3]))
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    return buffer.getvalue()


def _post_upload(client: TestClient, data: bytes, creator: str):
    return client.post(
        "/api/v1/upload",
        headers={"X-API-Key": RAW_KEY},
        files={"file": ("immutable.png", data, "image/png")},
        data={
            "provenance_json": json.dumps({
                "creator_name": creator,
                "ai_disclosure": "human",
                "ai_disclosure_complete": True,
            }),
            "options_json": json.dumps({
                "visible_watermark": False,
                "invisible_watermark": False,
            }),
        },
    )


def test_duplicate_same_tenant_reuses_registration_without_overwrite():
    with TestClient(main.app, raise_server_exceptions=False) as client:
        _ensure_client()
        data = _png_bytes()

        first = _post_upload(client, data, "Original Creator")
        assert first.status_code == 200, first.text
        first_body = first.json()
        omni_id = first_body["omni_id"]
        asset_id = first_body["asset_id"]

        duplicate = _post_upload(client, data, "Changed Creator")
        assert duplicate.status_code == 200, duplicate.text
        duplicate_body = duplicate.json()
        assert duplicate_body["registration_reused"] is True
        assert duplicate_body["omni_id"] == omni_id
        assert duplicate_body["asset_id"] == asset_id
        assert duplicate_body["creator_name"] == "Original Creator"

        report = client.get(
            f"/api/v1/assets/{omni_id}/report",
            headers={"X-API-Key": RAW_KEY},
        )
        assert report.status_code == 200, report.text
        body = report.json()
        assert body["creator_name"] == "Original Creator"
        assert body["stored_facts"]["identity"]["creator_name"] == "Original Creator"


def test_human_status_does_not_count_as_ai_use_disclosure():
    state = _normalize_ai_disclosure({
        "ai_disclosure": "human",
        "ai_disclosure_complete": True,
    })
    assert state["is_disclosed"] is False


def test_high_ai_signal_with_completed_human_form_gets_no_honest_ai_bonus():
    result = compute_copyright_readiness(AuthorshipSignals(
        human_creative_direction=True,
        ai_disclosure_complete=True,
        is_ai_disclosed=False,
        ai_detection_score=0.90,
    ))

    assert any(
        "without an explicit AI-use declaration" in factor
        for factor in result.factors_limiting
    )
    assert all(
        "explicitly disclosed" not in factor
        for factor in result.factors_supporting
    )
