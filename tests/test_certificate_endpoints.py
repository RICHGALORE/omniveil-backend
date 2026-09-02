import io
import json
import uuid

from fastapi.testclient import TestClient
from PIL import Image

import main
from app.api.v1.endpoints import certificate_verify
from app.core.tenant import hash_api_key
from app.db.models import Client, Contributor, LiveSplitSession
from app.db.session import SessionLocal


RAW_KEY = "ov_live_certificate_endpoint_test_key"
OTHER_KEY = "ov_live_certificate_endpoint_other_key"


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
    image = Image.new("RGB", (32, 32), tuple(uuid.uuid4().bytes[:3]))
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    return buffer.getvalue()


def _upload(client: TestClient, raw_key: str, filename: str) -> dict:
    response = client.post(
        "/api/v1/upload",
        headers={"X-API-Key": raw_key},
        files={"file": (filename, _png_bytes(), "image/png")},
        data={
            "provenance_json": json.dumps({"creator_name": "Certificate Tester"}),
            "options_json": "{}",
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_certificate_list_and_detail_are_tenant_scoped():
    with TestClient(main.app, raise_server_exceptions=False) as client:
        _ensure_client(RAW_KEY, "certificate-test-tenant", "cert-owner@example.com")
        _ensure_client(OTHER_KEY, "certificate-other-tenant", "cert-other@example.com")

        uploaded = _upload(client, RAW_KEY, "certificate-endpoint.png")
        owner_headers = {"X-API-Key": RAW_KEY}
        other_headers = {"X-API-Key": OTHER_KEY}

        listing = client.get("/api/v1/certificates", headers=owner_headers)
        assert listing.status_code == 200, listing.text
        matching = [
            item for item in listing.json()["items"]
            if item["omni_id"] == uploaded["omni_id"]
        ]
        assert len(matching) == 1

        cert_id = matching[0]["cert_id"]
        detail = client.get(f"/api/v1/certificates/{cert_id}", headers=owner_headers)
        assert detail.status_code == 200, detail.text
        assert detail.json()["asset"]["omni_id"] == uploaded["omni_id"]
        assert detail.json()["certificate"]["cert_id"] == cert_id

        hidden_list = client.get("/api/v1/certificates", headers=other_headers)
        assert hidden_list.status_code == 200
        assert all(item["cert_id"] != cert_id for item in hidden_list.json()["items"])

        hidden_detail = client.get(
            f"/api/v1/certificates/{cert_id}", headers=other_headers
        )
        assert hidden_detail.status_code == 404


def test_asset_list_is_tenant_scoped_but_public_registry_remains_public():
    with TestClient(main.app, raise_server_exceptions=False) as client:
        _ensure_client(RAW_KEY, "certificate-test-tenant", "cert-owner@example.com")
        _ensure_client(OTHER_KEY, "certificate-other-tenant", "cert-other@example.com")

        uploaded = _upload(client, RAW_KEY, "tenant-scope.png")

        owner_list = client.get(
            "/api/v1/assets", headers={"X-API-Key": RAW_KEY}
        )
        assert any(
            item["omni_id"] == uploaded["omni_id"]
            for item in owner_list.json()["items"]
        )

        other_list = client.get(
            "/api/v1/assets", headers={"X-API-Key": OTHER_KEY}
        )
        assert all(
            item["omni_id"] != uploaded["omni_id"]
            for item in other_list.json()["items"]
        )

        public_record = client.get(
            f"/api/v1/registry/assets/{uploaded['omni_id']}"
        )
        assert public_record.status_code == 200, public_record.text


def test_live_split_upload_persists_contributors_and_session():
    with TestClient(main.app, raise_server_exceptions=False) as client:
        _ensure_client(RAW_KEY, "certificate-test-tenant", "cert-owner@example.com")
        contributors = [
            {
                "name": "Writer One",
                "role": "Writer",
                "creative_contribution_pct": 60,
                "ownership_split_pct": 60,
                "ai_assisted_pct": 0,
            },
            {
                "name": "Producer Two",
                "role": "Producer",
                "creative_contribution_pct": 40,
                "ownership_split_pct": 40,
                "ai_assisted_pct": 20,
            },
        ]
        response = client.post(
            "/api/v1/upload",
            headers={"X-API-Key": RAW_KEY},
            files={"file": ("live-split.png", _png_bytes(), "image/png")},
            data={
                "provenance_json": json.dumps({
                    "creator_name": "Writer One",
                    "asset_title": "Live Split Test",
                    "ai_disclosure_complete": True,
                    "live_split": {
                        "session_name": "Live Split Test",
                        "contributors": contributors,
                    },
                }),
                "options_json": "{}",
            },
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["cert_id"]
        assert body["certificate_class"] == "live_split"

        db = SessionLocal()
        try:
            saved_contributors = (
                db.query(Contributor)
                .filter(Contributor.omni_id == body["omni_id"])
                .all()
            )
            assert {contributor.contributor_name for contributor in saved_contributors} == {
                "Writer One",
                "Producer Two",
            }
            session = (
                db.query(LiveSplitSession)
                .filter(LiveSplitSession.omni_id == body["omni_id"])
                .one()
            )
            assert session.status == "locked"
            assert session.tenant_id == "certificate-test-tenant"
            assert session.session_hash
        finally:
            db.close()


def test_live_split_rejects_invalid_ownership_total():
    with TestClient(main.app, raise_server_exceptions=False) as client:
        _ensure_client(RAW_KEY, "certificate-test-tenant", "cert-owner@example.com")
        response = client.post(
            "/api/v1/upload",
            headers={"X-API-Key": RAW_KEY},
            files={"file": ("invalid-split.png", _png_bytes(), "image/png")},
            data={
                "provenance_json": json.dumps({
                    "creator_name": "Split Tester",
                    "contributors": [
                        {"name": "Only Writer", "ownership_split_pct": 80}
                    ],
                }),
                "options_json": "{}",
            },
        )
        assert response.status_code == 400
        assert "must total 100%" in response.json()["detail"]


def test_public_certificate_verification_falls_back_to_database(tmp_path, monkeypatch):
    with TestClient(main.app, raise_server_exceptions=False) as client:
        _ensure_client(RAW_KEY, "certificate-test-tenant", "cert-owner@example.com")
        uploaded = _upload(client, RAW_KEY, "database-certificate.png")

        monkeypatch.setattr(certificate_verify, "CERTIFICATES_DIR", tmp_path)
        response = client.get(
            f"/api/v1/certificates/{uploaded['omni_id']}/verify"
        )

        assert response.status_code == 200, response.text
        assert response.json()["valid"] is True
        assert response.json()["cert_id"] == uploaded["cert_id"]
