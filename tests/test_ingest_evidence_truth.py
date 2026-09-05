import io
import json
import uuid

from fastapi.testclient import TestClient
from PIL import Image

import main
from app.core.tenant import hash_api_key
from app.db.models import Client
from app.db.session import SessionLocal


RAW_KEY = "ov_ingest_evidence_truth_test_key"
TENANT_ID = "ingest-evidence-truth-tenant"


def _ensure_client() -> None:
    db = SessionLocal()
    try:
        key_hash = hash_api_key(RAW_KEY)
        if not db.query(Client).filter(Client.api_key_hash == key_hash).first():
            db.add(Client(
                id=str(uuid.uuid4()),
                tenant_id=TENANT_ID,
                company_name="Ingest Evidence Truth Test",
                email="ingest-evidence-truth@example.com",
                status="approved",
                plan="creator",
                api_key_hash=key_hash,
            ))
            db.commit()
    finally:
        db.close()


def _png_bytes() -> bytes:
    image = Image.new("RGB", (24, 24), tuple(uuid.uuid4().bytes[:3]))
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    return buffer.getvalue()


def _upload(client: TestClient, provenance: dict) -> dict:
    response = client.post(
        "/api/v1/upload",
        headers={"X-API-Key": RAW_KEY},
        files={"file": (f"truth-{uuid.uuid4()}.png", _png_bytes(), "image/png")},
        data={
            "provenance_json": json.dumps(provenance),
            "options_json": json.dumps({
                "visible_watermark": False,
                "invisible_watermark": False,
            }),
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_creator_attribution_does_not_become_ownership_or_human_evidence():
    with TestClient(main.app, raise_server_exceptions=False) as client:
        _ensure_client()
        uploaded = _upload(client, {
            "creator_name": "Evidence Tester",
            "ai_disclosure": "human",
            "ai_disclosure_complete": True,
        })

        assert uploaded["creator_name"] == "Evidence Tester"
        assert uploaded["copyright_owner"] is None
        assert uploaded["license_type"] is None
        assert uploaded["section_a_human_contributions"]["contributions"] == []
        assert uploaded["section_a_human_contributions"]["contributors"] == []
        assert uploaded["section_c_ownership_splits"]["copyright_owner"] == ""
        assert uploaded["section_c_ownership_splits"]["splits"] == []

        detail = client.get(
            f"/api/v1/certificates/{uploaded['cert_id']}",
            headers={"X-API-Key": RAW_KEY},
        )
        assert detail.status_code == 200, detail.text
        certificate = detail.json()["certificate"]
        assert certificate["copyright_owner"] == ""
        assert certificate["section_c_ownership_splits"]["splits"] == []
        assert certificate["public_key_id"] == "OV-ROOT-DEV-001"


def test_ai_assisted_disclosure_is_not_rewritten_as_ai_generated():
    with TestClient(main.app, raise_server_exceptions=False) as client:
        _ensure_client()
        uploaded = _upload(client, {
            "creator_name": "Evidence Tester",
            "ai_disclosure": "ai_assisted",
            "ai_disclosure_complete": True,
            "ai_tools_used": ["Suno"],
            "human_creative_direction": True,
            "ai_modification_by_human": True,
        })

        assert uploaded["ai_disclosure"] == "ai_assisted"
        assert uploaded["content_label"] == "ai_assisted"
        assert uploaded["certificate_class"] == "ai_assisted"
        assert uploaded["section_b_ai_contributions"]["ai_tools_used"] == ["Suno"]
        assert uploaded["copyright_owner"] is None


def test_legacy_false_generated_flag_with_ai_tools_normalizes_to_ai_assisted():
    with TestClient(main.app, raise_server_exceptions=False) as client:
        _ensure_client()
        uploaded = _upload(client, {
            "creator_name": "Evidence Tester",
            "is_ai_generated": False,
            "ai_disclosure_complete": True,
            "ai_tools_used": ["Assistive Tool"],
            "human_creative_direction": True,
        })

        assert uploaded["ai_disclosure"] == "ai_assisted"
        assert uploaded["content_label"] == "ai_assisted"


def test_human_disclosure_rejects_specific_ai_tools_as_contradictory():
    with TestClient(main.app, raise_server_exceptions=False) as client:
        _ensure_client()
        response = client.post(
            "/api/v1/upload",
            headers={"X-API-Key": RAW_KEY},
            files={"file": ("contradiction.png", _png_bytes(), "image/png")},
            data={
                "provenance_json": json.dumps({
                    "creator_name": "Evidence Tester",
                    "ai_disclosure": "human",
                    "ai_tools_used": ["Suno"],
                }),
                "options_json": "{}",
            },
        )

        assert response.status_code == 400
        assert "cannot be human" in response.json()["detail"]
