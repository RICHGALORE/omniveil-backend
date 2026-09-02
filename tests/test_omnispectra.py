import uuid

from fastapi.testclient import TestClient

import main
from app.api.v1.endpoints import spectra as spectra_endpoint
from app.core.tenant import hash_api_key
from app.db.models import Client
from app.db.session import SessionLocal
from app.services.omnispectra import build_omnispectra_report


def test_invalid_c2pa_is_high_review_priority():
    report = build_omnispectra_report(
        filename="asset.jpg",
        anomaly={"anomaly_score": 0, "flags": [], "anomaly_summary": "No anomalies detected."},
        c2pa={
            "manifest_present": True,
            "validation_state": "invalid",
            "validation_error_count": 1,
            "actions": [],
        },
    )
    assert report["verdict"] == "high_review_priority"
    assert report["signals"]["content_credentials"]["risk"] == "high"
    assert any("C2PA" in reason for reason in report["reasons"])


def test_c2pa_absence_is_neutral_not_suspicious():
    report = build_omnispectra_report(
        filename="unsigned.jpg",
        anomaly={"anomaly_score": 0, "flags": [], "anomaly_summary": "No anomalies detected."},
        c2pa={
            "manifest_present": False,
            "validation_state": "not_present",
            "validation_error_count": 0,
        },
    )
    assert report["signals"]["content_credentials"]["risk"] == "neutral"
    assert report["verdict"] == "no_major_flags"


def test_high_synthetic_probability_is_flagged_with_provider_without_claiming_certainty():
    report = build_omnispectra_report(
        filename="clip.wav",
        ai_detection_score=0.91,
        detector_provider="sightengine",
        detector_model="genai",
        anomaly={"anomaly_score": 0, "flags": [], "anomaly_summary": "No anomalies detected."},
    )
    signal = report["signals"]["synthetic_detection"]
    assert signal["risk"] == "high"
    assert signal["probability_pct"] == 91.0
    assert signal["provider"] == "sightengine"
    assert signal["model"] == "genai"
    assert report["verdict"] == "high_review_priority"
    assert "does not independently prove" in signal["note"]


def _ensure_client(raw_key: str) -> None:
    main.init_db()
    db = SessionLocal()
    try:
        db.add(
            Client(
                id=str(uuid.uuid4()),
                tenant_id=f"spectra-{uuid.uuid4().hex}",
                company_name="OmniSpectra Test",
                email=f"spectra-{uuid.uuid4().hex}@example.com",
                status="approved",
                plan="creator",
                api_key_hash=hash_api_key(raw_key),
            )
        )
        db.commit()
    finally:
        db.close()


def test_ad_hoc_spectra_scan_requires_auth_and_returns_real_signal_shape(monkeypatch):
    raw_key = f"ov_live_spectra_{uuid.uuid4().hex}"
    _ensure_client(raw_key)

    monkeypatch.setattr(
        spectra_endpoint,
        "extract_metadata_service",
        lambda data, filename=None, mime_type=None: {"hashes": {"sha256": "a" * 64}},
    )
    monkeypatch.setattr(
        spectra_endpoint,
        "split_layers",
        lambda extraction: ({}, {"hashes": {"sha256": "a" * 64}}, {}),
    )
    monkeypatch.setattr(
        spectra_endpoint,
        "compute_metadata_anomaly_score",
        lambda **kwargs: {
            "anomaly_score": 15,
            "flags": [{"flag": "creator_missing", "severity": "Medium"}],
            "anomaly_summary": "1 anomaly flag detected.",
            "engine_version": "1.0.0",
        },
    )

    async def fake_detect(data, mime_type):
        return 0.12

    monkeypatch.setattr(spectra_endpoint, "_detect_synthetic", fake_detect)
    monkeypatch.setattr(
        spectra_endpoint,
        "_read_temp_c2pa",
        lambda data, filename: {
            "manifest_present": False,
            "validation_state": "not_present",
            "validation_error_count": 0,
        },
    )

    with TestClient(main.app, raise_server_exceptions=False) as client:
        denied = client.post(
            "/api/v1/spectra/scan",
            files={"file": ("asset.jpg", b"bytes", "image/jpeg")},
        )
        assert denied.status_code in (401, 403)

        response = client.post(
            "/api/v1/spectra/scan",
            headers={"X-API-Key": raw_key},
            files={"file": ("asset.jpg", b"bytes", "image/jpeg")},
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["engine"] == "Omni Veil OmniSpectra"
        assert body["scan_mode"] == "ad_hoc"
        assert body["sha256"] == "a" * 64
        synthetic = body["signals"]["synthetic_detection"]
        assert synthetic["probability"] == 0.12
        assert synthetic["provider"] == "sightengine"
        assert synthetic["model"] == "genai"
        assert body["signals"]["content_credentials"]["risk"] == "neutral"
        assert body["signals"]["metadata_anomalies"]["anomaly_score"] == 15
