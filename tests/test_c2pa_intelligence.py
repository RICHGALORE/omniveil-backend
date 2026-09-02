import json
import types
import uuid

from fastapi.testclient import TestClient

import main
from app.api.v1.endpoints import c2pa as c2pa_endpoint
from app.core.tenant import hash_api_key
from app.db.models import Client
from app.db.session import SessionLocal
from app.services import c2pa_intelligence


def _temp_asset(tmp_path):
    path = tmp_path / "asset.jpg"
    path.write_bytes(b"not-a-real-jpeg-but-reader-is-mocked")
    return path


def test_c2pa_reader_normalizes_active_manifest_and_actions(monkeypatch, tmp_path):
    manifest = {
        "active_manifest": "urn:c2pa:omniveil:test",
        "manifests": {
            "urn:c2pa:omniveil:test": {
                "claim_generator": "Adobe Photoshop/27.0",
                "title": "hero.jpg",
                "format": "image/jpeg",
                "instance_id": "xmp:iid:test",
                "ingredients": [{"title": "source.jpg"}],
                "assertions": [
                    {
                        "label": "c2pa.actions.v2",
                        "data": {
                            "actions": [
                                {"action": "c2pa.created"},
                                {"action": "c2pa.edited"},
                            ]
                        },
                    },
                    {"label": "stds.schema-org.CreativeWork", "data": {}},
                ],
            }
        },
    }

    class Reader:
        def __init__(self, path):
            self.path = path

        def json(self):
            return json.dumps(manifest)

    monkeypatch.setattr(
        c2pa_intelligence,
        "_load_sdk",
        lambda: types.SimpleNamespace(Reader=Reader),
    )

    result = c2pa_intelligence.read_c2pa_path(_temp_asset(tmp_path))
    assert result["manifest_present"] is True
    assert result["active_manifest"] == "urn:c2pa:omniveil:test"
    assert result["claim_generator"] == "Adobe Photoshop/27.0"
    assert result["ingredient_count"] == 1
    assert result["assertion_count"] == 2
    assert result["actions"] == ["c2pa.created", "c2pa.edited"]
    assert result["validation_state"] == "no_reported_errors"
    assert result["validation_error_count"] == 0
    assert "not standalone proof of human authorship" in result["evidence_note"].lower()


def test_c2pa_reader_preserves_validation_failure_as_evidence(monkeypatch, tmp_path):
    manifest = {
        "active_manifest": "urn:c2pa:bad",
        "validation_status": [
            {
                "code": "assertion.dataHash.mismatch",
                "success": False,
                "explanation": "Asset hash did not match the claim.",
            }
        ],
        "manifests": {"urn:c2pa:bad": {"title": "changed.jpg", "assertions": []}},
    }

    class Reader:
        def __init__(self, path):
            pass

        def json(self):
            return manifest

    monkeypatch.setattr(
        c2pa_intelligence,
        "_load_sdk",
        lambda: types.SimpleNamespace(Reader=Reader),
    )

    result = c2pa_intelligence.read_c2pa_path(_temp_asset(tmp_path))
    assert result["manifest_present"] is True
    assert result["validation_state"] == "invalid"
    assert result["validation_error_count"] == 1
    assert result["validation_status"][0]["code"] == "assertion.dataHash.mismatch"


def test_c2pa_reader_handles_manifest_not_found(monkeypatch, tmp_path):
    class Reader:
        def __init__(self, path):
            raise RuntimeError("ManifestNotFound: no JUMBF manifest store")

    monkeypatch.setattr(
        c2pa_intelligence,
        "_load_sdk",
        lambda: types.SimpleNamespace(Reader=Reader),
    )

    result = c2pa_intelligence.read_c2pa_path(_temp_asset(tmp_path))
    assert result["manifest_present"] is False
    assert result["validation_state"] == "not_present"
    assert result["validation_status"] == []


def _ensure_client(raw_key: str) -> None:
    db = SessionLocal()
    try:
        db.add(
            Client(
                id=str(uuid.uuid4()),
                tenant_id=f"c2pa-{uuid.uuid4().hex}",
                company_name="C2PA Test",
                email=f"c2pa-{uuid.uuid4().hex}@example.com",
                status="approved",
                plan="creator",
                api_key_hash=hash_api_key(raw_key),
            )
        )
        db.commit()
    finally:
        db.close()


def test_c2pa_ad_hoc_read_endpoint_is_authenticated_and_returns_normalized_summary(monkeypatch):
    raw_key = f"ov_live_c2pa_{uuid.uuid4().hex}"
    _ensure_client(raw_key)
    stub = {
        "engine": "Omni Veil C2PA Intelligence",
        "engine_version": "1.0.0",
        "sdk": "c2pa-python",
        "sdk_version": "0.37.7",
        "manifest_present": False,
        "validation_state": "not_present",
        "validation_status": [],
        "validation_error_count": 0,
    }
    monkeypatch.setattr(c2pa_endpoint, "read_c2pa_path", lambda path: stub)

    with TestClient(main.app, raise_server_exceptions=False) as client:
        denied = client.post(
            "/api/v1/c2pa/read",
            files={"file": ("asset.jpg", b"bytes", "image/jpeg")},
        )
        assert denied.status_code in (401, 403)

        response = client.post(
            "/api/v1/c2pa/read",
            headers={"X-API-Key": raw_key},
            files={"file": ("asset.jpg", b"bytes", "image/jpeg")},
        )
        assert response.status_code == 200, response.text
        assert response.json()["filename"] == "asset.jpg"
        assert response.json()["size_bytes"] == 5
        assert response.json()["c2pa"] == stub
