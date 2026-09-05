import io
import json
import uuid

from fastapi.testclient import TestClient
from PIL import Image

import main
from app.api.v1.endpoints import spectra as spectra_endpoint
from app.core.tenant import hash_api_key
from app.db.forensic_models import ForensicObservation
from app.db.models import Asset, Client
from app.db.session import SessionLocal


def _png_bytes() -> bytes:
    image = Image.new("RGB", (20, 20), (22, 44, 66))
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    return buffer.getvalue()


def _ensure_client(raw_key: str, tenant_id: str) -> None:
    main.init_db()
    db = SessionLocal()
    try:
        if not db.query(Client).filter(Client.tenant_id == tenant_id).first():
            db.add(
                Client(
                    id=str(uuid.uuid4()),
                    tenant_id=tenant_id,
                    company_name="Forensic Refresh Test",
                    email=f"forensic-{uuid.uuid4().hex}@example.com",
                    status="approved",
                    plan="creator",
                    api_key_hash=hash_api_key(raw_key),
                )
            )
            db.commit()
    finally:
        db.close()


def test_registered_detector_refresh_appends_evidence_without_rewriting_registration(monkeypatch):
    raw_key = f"ov_live_forensic_{uuid.uuid4().hex}"
    tenant_id = f"forensic-{uuid.uuid4().hex}"
    _ensure_client(raw_key, tenant_id)

    async def fake_detectors(data, *, mime_type, filename=None):
        assert data
        assert mime_type == "image/png"
        return [
            {
                "provider": "sightengine",
                "model": "genai",
                "signal": "synthetic_media_probability",
                "probability": 0.21,
                "status": "available",
                "details": {"source": "test"},
            },
            {
                "provider": "hive",
                "model": "ai_generated_media",
                "signal": "synthetic_media_probability",
                "probability": 0.87,
                "status": "available",
                "details": {"source": "test"},
            },
        ]

    monkeypatch.setattr(spectra_endpoint, "run_synthetic_detectors", fake_detectors)

    with TestClient(main.app, raise_server_exceptions=False) as client:
        upload = client.post(
            "/api/v1/upload",
            headers={"X-API-Key": raw_key},
            files={"file": ("flagship-proof.png", _png_bytes(), "image/png")},
            data={
                "provenance_json": json.dumps(
                    {
                        "creator_name": "Forensic Test Creator",
                        "ai_disclosure": "human",
                        "ai_disclosure_complete": True,
                    }
                ),
                "options_json": json.dumps(
                    {"visible_watermark": False, "invisible_watermark": False}
                ),
            },
        )
        assert upload.status_code == 200, upload.text
        registered = upload.json()
        omni_id = registered["omni_id"]
        original_trust_score = registered["trust_score"]
        original_ai_score = registered["ai_detection_score"]

        refresh = client.post(
            f"/api/v1/spectra/assets/{omni_id}/detectors",
            headers={"X-API-Key": raw_key},
        )
        assert refresh.status_code == 200, refresh.text
        refreshed = refresh.json()
        assert refreshed["detector_refresh"]["persisted_observation_count"] == 2
        assert refreshed["detector_refresh"]["providers"] == ["hive", "sightengine"]
        assert refreshed["detector_refresh"]["registration_rewritten"] is False
        assert refreshed["detector_refresh"]["trust_score_rewritten"] is False

        summary = refreshed["signals"]["synthetic_detector_summary"]
        assert summary["provider_count"] == 2
        assert summary["consensus_score"] is None
        assert refreshed["verdict"] == "high_review_priority"

        graph_response = client.get(
            f"/api/v1/evidence/assets/{omni_id}",
            headers={"X-API-Key": raw_key},
        )
        assert graph_response.status_code == 200, graph_response.text
        graph = graph_response.json()
        assert graph["graph_version"] == "1.3"
        provider_nodes = [
            node
            for node in graph["nodes"]
            if node["evidence_class"] == "forensic_observation"
            and node["data"].get("provider") in {"hive", "sightengine"}
        ]
        assert {node["data"]["provider"] for node in provider_nodes} == {
            "hive",
            "sightengine",
        }

    db = SessionLocal()
    try:
        asset = (
            db.query(Asset)
            .filter(Asset.omni_id == omni_id, Asset.tenant_id == tenant_id)
            .one()
        )
        assert asset.trust_score == original_trust_score
        assert asset.ai_detection_score == original_ai_score

        observations = (
            db.query(ForensicObservation)
            .filter(
                ForensicObservation.omni_id == omni_id,
                ForensicObservation.tenant_id == tenant_id,
            )
            .all()
        )
        assert len(observations) == 2
        assert {row.provider for row in observations} == {"hive", "sightengine"}
    finally:
        db.close()
