import io
import json
import uuid

from fastapi.testclient import TestClient
from PIL import Image

import main
from app.core.tenant import hash_api_key
from app.db.models import Asset, Client
from app.db.session import SessionLocal


RAW_KEY = "ov_fact_integrity_test_key"
TENANT_ID = "fact-integrity-test-tenant"
OTHER_KEY = "ov_fact_integrity_other_key"
OTHER_TENANT_ID = "fact-integrity-other-tenant"


def _ensure_client(raw_key: str, tenant_id: str, email: str) -> None:
    db = SessionLocal()
    try:
        key_hash = hash_api_key(raw_key)
        if not db.query(Client).filter(Client.api_key_hash == key_hash).first():
            db.add(Client(
                id=str(uuid.uuid4()),
                tenant_id=tenant_id,
                company_name=f"{tenant_id} Test",
                email=email,
                status="approved",
                plan="creator",
                api_key_hash=key_hash,
            ))
            db.commit()
    finally:
        db.close()


def _png_bytes() -> bytes:
    image = Image.new("RGB", (28, 28), tuple(uuid.uuid4().bytes[:3]))
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    return buffer.getvalue()


def _upload(client: TestClient) -> dict:
    response = client.post(
        "/api/v1/upload",
        headers={"X-API-Key": RAW_KEY},
        files={"file": (f"integrity-{uuid.uuid4()}.png", _png_bytes(), "image/png")},
        data={
            "provenance_json": json.dumps({
                "creator_name": "Integrity Creator",
                "copyright_owner": "Integrity Rights LLC",
                "license_type": "Integrity Test License",
                "ai_disclosure": "human",
                "ai_disclosure_complete": True,
                "human_creative_direction": True,
            }),
            "options_json": json.dumps({
                "visible_watermark": False,
                "invisible_watermark": False,
            }),
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_clean_asset_integrity_is_consistent_and_read_only():
    with TestClient(main.app, raise_server_exceptions=False) as client:
        _ensure_client(RAW_KEY, TENANT_ID, "fact-integrity@example.com")
        uploaded = _upload(client)
        headers = {"X-API-Key": RAW_KEY}

        before = client.get(
            f"/api/v1/assets/{uploaded['omni_id']}/report",
            headers=headers,
        ).json()["total_verifications"]
        assert before == 0

        response = client.get(
            f"/api/v1/assets/{uploaded['omni_id']}/integrity",
            headers=headers,
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["status"] == "consistent"
        assert body["mismatch_count"] == 0
        assert body["unavailable_count"] == 0
        assert {check["name"] for check in body["checks"]} == {
            "signed_certificate",
            "provenance_manifest",
            "verification_counter",
        }
        assert all(check["status"] == "pass" for check in body["checks"])
        assert body["stored_facts"]["identity"]["creator_name"] == "Integrity Creator"
        assert body["stored_facts"]["rights"]["copyright_owner"] == "Integrity Rights LLC"

        after = client.get(
            f"/api/v1/assets/{uploaded['omni_id']}/report",
            headers=headers,
        ).json()["total_verifications"]
        assert after == 0, "integrity/report reads must not count as verifications"


def test_real_verification_keeps_counter_and_log_integrity_aligned():
    with TestClient(main.app, raise_server_exceptions=False) as client:
        _ensure_client(RAW_KEY, TENANT_ID, "fact-integrity@example.com")
        uploaded = _upload(client)
        headers = {"X-API-Key": RAW_KEY}

        verified = client.get(f"/api/v1/verify/{uploaded['omni_id']}")
        assert verified.status_code == 200, verified.text
        assert verified.json()["total_verifications"] == 1

        integrity = client.get(
            f"/api/v1/assets/{uploaded['omni_id']}/integrity",
            headers=headers,
        )
        assert integrity.status_code == 200, integrity.text
        body = integrity.json()
        assert body["status"] == "consistent"
        counter = next(
            check for check in body["checks"] if check["name"] == "verification_counter"
        )
        assert counter["status"] == "pass"
        assert counter["stored_total_verifications"] == 1
        assert counter["matching_log_count"] == 1


def test_rights_drift_is_detected_against_certificate_and_manifest():
    with TestClient(main.app, raise_server_exceptions=False) as client:
        _ensure_client(RAW_KEY, TENANT_ID, "fact-integrity@example.com")
        uploaded = _upload(client)

        db = SessionLocal()
        try:
            asset = db.query(Asset).filter(Asset.omni_id == uploaded["omni_id"]).one()
            asset.copyright_owner = "Drifted Rights LLC"
            db.commit()
        finally:
            db.close()

        response = client.get(
            f"/api/v1/assets/{uploaded['omni_id']}/integrity",
            headers={"X-API-Key": RAW_KEY},
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["status"] == "review_required"
        assert body["mismatch_count"] >= 2

        certificate = next(
            check for check in body["checks"] if check["name"] == "signed_certificate"
        )
        manifest = next(
            check for check in body["checks"] if check["name"] == "provenance_manifest"
        )
        assert certificate["status"] == "fail"
        assert manifest["status"] == "fail"
        assert any(
            item["field"] == "copyright_owner"
            for item in certificate["mismatches"]
        )
        assert any(
            item["field"] == "copyright_owner"
            for item in manifest["mismatches"]
        )


def test_integrity_endpoint_is_tenant_scoped():
    with TestClient(main.app, raise_server_exceptions=False) as client:
        _ensure_client(RAW_KEY, TENANT_ID, "fact-integrity@example.com")
        _ensure_client(
            OTHER_KEY,
            OTHER_TENANT_ID,
            "fact-integrity-other@example.com",
        )
        uploaded = _upload(client)

        hidden = client.get(
            f"/api/v1/assets/{uploaded['omni_id']}/integrity",
            headers={"X-API-Key": OTHER_KEY},
        )
        assert hidden.status_code == 404
