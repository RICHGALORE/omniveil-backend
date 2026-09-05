import base64
import json
import uuid

from fastapi.testclient import TestClient

import main
from app.core.tenant import hash_api_key
from app.db.models import Client
from app.db.session import SessionLocal


# Valid 1x1 PNG. Keeping the fixture tiny makes this an API/integration test,
# not an image-processing benchmark.
PNG_1X1 = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAusB9Wl2n1cAAAAASUVORK5CYII="
)


def _ensure_client(raw_key: str, tenant_id: str) -> None:
    main.init_db()
    db = SessionLocal()
    try:
        key_hash = hash_api_key(raw_key)
        if not db.query(Client).filter(Client.api_key_hash == key_hash).first():
            db.add(
                Client(
                    id=str(uuid.uuid4()),
                    tenant_id=tenant_id,
                    company_name="Omni Veil E2E Test",
                    email=f"e2e-{uuid.uuid4().hex}@example.com",
                    status="approved",
                    plan="creator",
                    api_key_hash=key_hash,
                )
            )
            db.commit()
    finally:
        db.close()


def _append_humanproof_event(client, api_key, session_id, event_type, **extra):
    payload = {
        "event_type": event_type,
        "source_type": "creative_app",
        "source_name": "Heavy Handed Workflow",
        "creator_id": "e2e-creator",
        "payload": extra.pop("payload", {}),
        **extra,
    }
    response = client.post(
        f"/api/v1/humanproof/sessions/{session_id}/events",
        headers={"X-API-Key": api_key},
        json=payload,
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_full_trust_os_asset_flow_upload_humanproof_registry_verify_certificate_spectra(monkeypatch):
    """Prove the launch-critical evidence path works as one connected system.

    This deliberately crosses module boundaries instead of mocking the API
    surfaces independently:

      Upload -> signed certificate -> HumanProof -> public Registry -> Verify
      -> certificate detail -> OmniSpectra.

    External synthetic detection is disabled so CI remains deterministic. C2PA
    still runs normally and a file without Content Credentials must be treated
    as neutral rather than suspicious.
    """
    api_key = f"ov_live_e2e_{uuid.uuid4().hex}"
    tenant_id = f"trust-os-e2e-{uuid.uuid4().hex}"
    _ensure_client(api_key, tenant_id)

    # No third-party network calls in the regression suite. The absence of a
    # model result must remain an explicit unknown signal in OmniSpectra.
    from app.api.v1.endpoints import ingest as ingest_endpoint
    from app.api.v1.endpoints import spectra as spectra_endpoint

    async def no_image_detector(*args, **kwargs):
        return None

    async def no_synthetic_detectors(*args, **kwargs):
        return []

    monkeypatch.setattr(ingest_endpoint.hive, "detect_ai_image", no_image_detector)
    monkeypatch.setattr(spectra_endpoint, "run_synthetic_detectors", no_synthetic_detectors)

    provenance = {
        "creator_name": "Marlon Rich Galore Cooper",
        "copyright_owner": "Heavy Handed Productions",
        "license_type": "all-rights-reserved",
        "asset_title": "Omni Veil E2E Proof",
        "is_ai_generated": False,
        "ai_disclosure_complete": True,
        "ai_tools_used": [],
        "human_creative_direction": True,
        "human_editing_present": True,
        "human_transformation_present": True,
        "human_authorship_summary": "Human-directed flagship Trust OS regression asset.",
    }

    with TestClient(main.app, raise_server_exceptions=False) as client:
        # 1. Upload / register / certificate issuance.
        upload = client.post(
            "/api/v1/upload",
            headers={"X-API-Key": api_key},
            files={"file": ("heavy-handed-e2e.png", PNG_1X1, "image/png")},
            data={
                "provenance_json": json.dumps(provenance),
                "options_json": json.dumps({
                    "visible_watermark": False,
                    "invisible_watermark": False,
                }),
            },
        )
        assert upload.status_code == 200, upload.text
        asset = upload.json()
        omni_id = asset["omni_id"]
        cert_id = asset["cert_id"]
        assert omni_id.startswith("OV-")
        assert len(asset["sha256"]) == 64
        assert asset["creator_name"] == "Marlon Rich Galore Cooper"
        assert asset["ai_disclosure"] == "human"

        # 2. Start HumanProof creation evidence and bind it to the actual
        # registered fingerprint, not merely to a user-provided identifier.
        start = client.post(
            "/api/v1/humanproof/sessions",
            headers={"X-API-Key": api_key},
            json={
                "creator_id": "e2e-creator",
                "source_type": "creative_app",
                "source_name": "Heavy Handed Workflow",
                "location": {
                    "level": "coarse",
                    "public_summary": "Las Vegas, NV",
                },
                "payload": {"project_name": "Omni Veil E2E Proof"},
            },
        )
        assert start.status_code == 201, start.text
        session_id = start.json()["session_id"]

        _append_humanproof_event(
            client,
            api_key,
            session_id,
            "source_captured",
            payload={"source_role": "original_creation"},
        )
        _append_humanproof_event(
            client,
            api_key,
            session_id,
            "ai_tool_disclosed",
            ai_disclosure={"used": False, "tools": [], "role": None},
            payload={"attestation": "No AI tools used in this test workflow"},
        )
        _append_humanproof_event(
            client,
            api_key,
            session_id,
            "asset_registered",
            omni_id=omni_id,
            payload={"sha256": asset["sha256"]},
        )

        close = client.post(
            f"/api/v1/humanproof/sessions/{session_id}/close",
            headers={"X-API-Key": api_key},
            json={"source_type": "creative_app", "source_name": "Heavy Handed Workflow"},
        )
        assert close.status_code == 200, close.text
        closed = close.json()
        assert closed["status"] == "complete"
        assert closed["chain_integrity"]["valid"] is True
        assert closed["omni_id"] == omni_id

        # 3. Public Registry exposes only the safe HumanProof summary.
        registry = client.get(f"/api/v1/registry/assets/{omni_id}")
        assert registry.status_code == 200, registry.text
        registry_body = registry.json()
        hp = registry_body["humanproof"]
        assert hp["status"] == "complete"
        assert hp["chain_integrity"]["valid"] is True
        assert hp["asset_bound"] is True
        assert hp["location"] == {
            "level": "coarse",
            "public_summary": "Las Vegas, NV",
        }
        serialized_registry = json.dumps(registry_body)
        assert "e2e-creator" not in serialized_registry
        assert "source_role" not in serialized_registry
        assert "evidence_hash" not in serialized_registry

        # 4. Standard verification sees the same HumanProof state.
        verify = client.get(f"/api/v1/verify/{omni_id}")
        assert verify.status_code == 200, verify.text
        verify_body = verify.json()
        assert verify_body["verified"] is True
        assert verify_body["humanproof"]["chain_integrity"]["valid"] is True

        # 5. Certificate detail is tenant-scoped and carries the public-safe
        # HumanProof summary without embedding private session evidence.
        certificate = client.get(
            f"/api/v1/certificates/{cert_id}",
            headers={"X-API-Key": api_key},
        )
        assert certificate.status_code == 200, certificate.text
        certificate_body = certificate.json()
        assert certificate_body["humanproof"]["status"] == "complete"
        assert certificate_body["asset"]["omni_id"] == omni_id

        # 6. OmniSpectra orchestrates independent forensic evidence. The tiny
        # PNG has no C2PA manifest; that must remain neutral, not become a fraud
        # flag. HumanProof integrity remains its own signal.
        spectra = client.get(
            f"/api/v1/spectra/assets/{omni_id}",
            headers={"X-API-Key": api_key},
        )
        assert spectra.status_code == 200, spectra.text
        spectra_body = spectra.json()
        assert spectra_body["scan_mode"] == "registered"
        assert spectra_body["omni_id"] == omni_id
        assert spectra_body["signals"]["humanproof"]["chain_valid"] is True
        assert spectra_body["signals"]["content_credentials"]["risk"] == "neutral"
        assert spectra_body["signals"]["synthetic_detection"]["risk"] == "unknown"
        assert spectra_body["signals"]["synthetic_detector_summary"]["provider_count"] == 0
        assert spectra_body["verdict"] in {"no_major_flags", "review_recommended"}
