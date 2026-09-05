import io
import json
import uuid

from fastapi.testclient import TestClient
from PIL import Image

import main
from app.core.tenant import hash_api_key
from app.db.models import Client
from app.db.session import SessionLocal


FORBIDDEN_PUBLIC_VALUES = (
    "latitude",
    "longitude",
    "private-creator-id",
    "Private DAW Name",
    "private_project_name",
    "private_source_path",
    "internal evidence note",
)


def _identity():
    token = uuid.uuid4().hex
    return (
        f"ov_live_hp_public_{token}",
        f"hp-public-{token}",
        f"hp-public-{token}@example.com",
    )


def _ensure_client(raw_key: str, tenant_id: str, email: str) -> None:
    db = SessionLocal()
    try:
        db.add(
            Client(
                id=str(uuid.uuid4()),
                tenant_id=tenant_id,
                company_name="HumanProof Public Integration Test",
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


def _upload(client: TestClient, raw_key: str, filename: str = "humanproof-public.png") -> dict:
    response = client.post(
        "/api/v1/upload",
        headers={"X-API-Key": raw_key},
        files={"file": (filename, _png_bytes(), "image/png")},
        data={
            "provenance_json": json.dumps({"creator_name": "HumanProof Public Tester"}),
            "options_json": "{}",
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


def _complete_humanproof(
    client: TestClient,
    raw_key: str,
    omni_id: str,
    *,
    privacy_mode: str = "proof",
) -> dict:
    headers = {"X-API-Key": raw_key}
    started = client.post(
        "/api/v1/humanproof/sessions",
        headers=headers,
        json={
            "creator_id": "private-creator-id",
            "source_type": "daw",
            "source_name": "Private DAW Name",
            "location": {
                "level": "precise_private",
                "latitude": 36.1716,
                "longitude": -115.1391,
            },
            "payload": {
                "private_project_name": "Do Not Publish",
                "privacy_mode": privacy_mode,
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
            "source_name": "Private DAW Name",
            "creator_id": "private-creator-id",
            "payload": {"private_source_path": "/secret/session.logicx"},
        },
    )
    assert source.status_code == 201, source.text

    disclosure = client.post(
        f"/api/v1/humanproof/sessions/{session_id}/events",
        headers=headers,
        json={
            "event_type": "ai_tool_disclosed",
            "source_type": "web",
            "source_name": "Private Disclosure Console",
            "creator_id": "private-creator-id",
            "ai_disclosure": {"used": True, "tools": ["ChatGPT"], "role": "assist"},
            "payload": {"private_note": "internal evidence note"},
        },
    )
    assert disclosure.status_code == 201, disclosure.text

    registered = client.post(
        f"/api/v1/humanproof/sessions/{session_id}/events",
        headers=headers,
        json={
            "event_type": "asset_registered",
            "source_type": "registry",
            "source_name": "Private Registry Source",
            "creator_id": "private-creator-id",
            "omni_id": omni_id,
            "payload": {"omni_id": omni_id},
        },
    )
    assert registered.status_code == 201, registered.text

    closed = client.post(
        f"/api/v1/humanproof/sessions/{session_id}/close",
        headers=headers,
        json={"source_type": "web", "source_name": "Private Close Source"},
    )
    assert closed.status_code == 200, closed.text
    assert closed.json()["status"] == "complete"
    return closed.json()


def _assert_compact_public_summary(summary: dict, *, privacy_mode: str = "proof") -> None:
    assert summary["status"] == "complete"
    assert summary["privacy_mode"] == privacy_mode
    assert summary["event_count"] == 5
    assert summary["chain_integrity"] == {"valid": True, "event_count": 5}
    assert summary["ai_disclosure"] == {
        "used": True,
        "tools": ["ChatGPT"],
        "role": "assist",
    }
    assert summary["location"] == {
        "level": "precise_private",
        "public_summary": "private",
    }
    assert summary["asset_bound"] is True

    serialized = json.dumps(summary)
    for forbidden in (*FORBIDDEN_PUBLIC_VALUES, "evidence_hash", "events"):
        assert forbidden not in serialized


def _assert_sanitized_public_timeline(payload: dict, *, privacy_mode: str) -> None:
    assert payload["status"] == "complete"
    assert payload["privacy_mode"] == privacy_mode
    assert payload["chain_integrity"]["valid"] is True
    assert payload["event_count"] == 5
    assert len(payload["events"]) == 5

    first_location = payload["events"][0]["location"]
    assert first_location == {
        "level": "precise_private",
        "public_summary": "private",
    }

    for event in payload["events"]:
        assert "payload" not in event
        assert "source_name" not in event
        assert "creator_id" not in event

    serialized = json.dumps(payload)
    for forbidden in FORBIDDEN_PUBLIC_VALUES:
        assert forbidden not in serialized


def test_humanproof_summary_is_shared_across_verify_registry_certificate_and_public_endpoint_without_private_evidence():
    raw_key, tenant_id, email = _identity()
    with TestClient(main.app, raise_server_exceptions=False) as client:
        _ensure_client(raw_key, tenant_id, email)
        uploaded = _upload(client, raw_key)
        _complete_humanproof(client, raw_key, uploaded["omni_id"], privacy_mode="proof")

        verify = client.get(f"/api/v1/verify/{uploaded['omni_id']}")
        assert verify.status_code == 200, verify.text
        _assert_compact_public_summary(verify.json()["humanproof"])

        registry = client.get(f"/api/v1/registry/assets/{uploaded['omni_id']}")
        assert registry.status_code == 200, registry.text
        _assert_compact_public_summary(registry.json()["humanproof"])

        certificate = client.get(
            f"/api/v1/certificates/{uploaded['cert_id']}",
            headers={"X-API-Key": raw_key},
        )
        assert certificate.status_code == 200, certificate.text
        _assert_compact_public_summary(certificate.json()["humanproof"])

        public_hp = client.get(f"/api/v1/humanproof/assets/{uploaded['omni_id']}/public")
        assert public_hp.status_code == 200, public_hp.text
        _assert_sanitized_public_timeline(public_hp.json(), privacy_mode="proof")


def test_private_humanproof_is_hidden_across_every_public_surface():
    raw_key, tenant_id, email = _identity()
    with TestClient(main.app, raise_server_exceptions=False) as client:
        _ensure_client(raw_key, tenant_id, email)
        uploaded = _upload(client, raw_key, "private-humanproof.png")
        _complete_humanproof(client, raw_key, uploaded["omni_id"], privacy_mode="private")

        verify = client.get(f"/api/v1/verify/{uploaded['omni_id']}")
        assert verify.status_code == 200, verify.text
        assert verify.json()["humanproof"] is None

        registry = client.get(f"/api/v1/registry/assets/{uploaded['omni_id']}")
        assert registry.status_code == 200, registry.text
        assert registry.json()["humanproof"] is None

        certificate = client.get(
            f"/api/v1/certificates/{uploaded['cert_id']}",
            headers={"X-API-Key": raw_key},
        )
        assert certificate.status_code == 200, certificate.text
        assert certificate.json()["humanproof"] is None

        public_hp = client.get(f"/api/v1/humanproof/assets/{uploaded['omni_id']}/public")
        assert public_hp.status_code == 404
        assert public_hp.json()["detail"] == "HumanProof record not found"


def test_public_mode_keeps_sanitized_timeline_until_selected_evidence_publishing_exists():
    raw_key, tenant_id, email = _identity()
    with TestClient(main.app, raise_server_exceptions=False) as client:
        _ensure_client(raw_key, tenant_id, email)
        uploaded = _upload(client, raw_key, "public-mode-humanproof.png")
        _complete_humanproof(client, raw_key, uploaded["omni_id"], privacy_mode="public")

        verify = client.get(f"/api/v1/verify/{uploaded['omni_id']}")
        assert verify.status_code == 200, verify.text
        _assert_compact_public_summary(
            verify.json()["humanproof"],
            privacy_mode="public",
        )

        response = client.get(f"/api/v1/humanproof/assets/{uploaded['omni_id']}/public")
        assert response.status_code == 200, response.text
        _assert_sanitized_public_timeline(response.json(), privacy_mode="public")


def test_assets_without_humanproof_return_explicit_null_summary():
    raw_key, tenant_id, email = _identity()
    with TestClient(main.app, raise_server_exceptions=False) as client:
        _ensure_client(raw_key, tenant_id, email)
        uploaded = _upload(client, raw_key, "no-humanproof.png")

        verify = client.get(f"/api/v1/verify/{uploaded['omni_id']}")
        assert verify.status_code == 200, verify.text
        assert verify.json()["humanproof"] is None

        registry = client.get(f"/api/v1/registry/assets/{uploaded['omni_id']}")
        assert registry.status_code == 200, registry.text
        assert registry.json()["humanproof"] is None
