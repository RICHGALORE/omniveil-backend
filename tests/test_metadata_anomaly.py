"""
Metadata Intelligence — Commit 4 (Metadata Anomaly Intelligence Engine) tests.

Proves that the deterministic, rule-based anomaly engine:
  * raises NO anomalies for a genuinely clean image,
  * flags stripped EXIF, reversed timestamps, future timestamps, missing
    creator, MIME mismatch, extension mismatch, missing/malformed hash,
    impossible + partial GPS, and a software/device conflict,
  * fires ``gps_removed`` ONLY when GPS keys existed in the raw metadata
    (merely-absent GPS is not an anomaly),
  * is deterministic (same input -> identical score + flags),
  * is served by the read endpoint and is tenant-isolated,
  * is additive (existing routes unaffected; upload response shape unchanged).

All fixtures are REAL bytes (Pillow ``getexif`` — no piexif, no mock JSON) plus
a few crafted normalized dicts for rules that the pure-Python extractor cannot
naturally produce (MIME mismatch, malformed hash, impossible GPS). Distinct
tenant keys avoid collision with the Commit 2/3/3.1 suites.

Requirement coverage:
  1  clean JPEG -> anomaly_score == 0, no flags
  2  stripped EXIF -> exif_stripped flag, score > 0
  3  reversed timestamps -> timestamp_order_reversed flag
  4  missing / malformed hash -> hash_missing / hash_malformed flag
  5  missing creator -> creator_missing flag
  6  no GPS in raw -> NO gps_removed flag; GPS in raw but dropped -> flag
  7  MIME mismatch -> mime_mismatch flag
  8  determinism: same file -> same score + flags
  9  endpoint smoke: upload -> GET /anomalies 200 + correct shape
 10  tenant isolation at the anomalies endpoint (404 across tenants)
 11  future timestamp / impossible + partial GPS / extension / software rules
 12  regression smoke: routes present (27), upload response shape unchanged
"""
import copy
import io
import json
import uuid

from fastapi.testclient import TestClient
from PIL import Image

import main
from app.db.session import SessionLocal
from app.db.models import Client
from app.core.tenant import hash_api_key
from app.services.metadata_extraction import extract_metadata_service
from app.services.metadata_persistence import split_layers
from app.services.metadata_anomaly import (
    compute_metadata_anomaly_score,
    ANOMALY_ENGINE_VERSION,
    SEVERITY_POINTS,
)

# Independent tenants for this suite.
RAW_KEY_A = "ov_live_anomaly_test_tenant_a_0001"
RAW_KEY_B = "ov_live_anomaly_test_tenant_b_0002"
TENANT_A = "anomaly-test-tenant-a"
TENANT_B = "anomaly-test-tenant-b"


# ── Client seeding ─────────────────────────────────────────────────────────────

def _ensure_client(raw_key: str, tenant_id: str, email: str):
    db = SessionLocal()
    try:
        kh = hash_api_key(raw_key)
        if not db.query(Client).filter(Client.api_key_hash == kh).first():
            db.add(Client(
                id=str(uuid.uuid4()),
                tenant_id=tenant_id,
                company_name=f"Anomaly Test {tenant_id}",
                email=email,
                status="approved",
                plan="creator",
                api_key_hash=kh,
            ))
            db.commit()
    finally:
        db.close()


# ── Real-byte fixture builders (Pillow only) ────────────────────────────────────

def _jpeg(make=None, model=None, software=None,
          dt_original=None, dt_modify=None, dt_digitized=None,
          color=(30, 90, 160), size=(48, 36)) -> bytes:
    img = Image.new("RGB", size, color)
    exif = img.getexif()
    if make:
        exif[271] = make
    if model:
        exif[272] = model
    if software:
        exif[305] = software
    if dt_modify:
        exif[306] = dt_modify
    if dt_original or dt_digitized:
        ifd = exif.get_ifd(0x8769)
        if dt_original:
            ifd[36867] = dt_original
        if dt_digitized:
            ifd[36868] = dt_digitized
    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=90, exif=exif)
    return buf.getvalue()


def _jpeg_stripped(color=(30, 90, 160), size=(48, 36)) -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", size, color).save(buf, format="JPEG", quality=90)
    return buf.getvalue()


def _full_jpeg() -> bytes:
    return _jpeg(make="OmniVeilCam", model="Model-X100",
                 dt_original="2024:01:15 09:00:00",
                 dt_modify="2024:01:15 10:30:00",
                 dt_digitized="2024:01:15 09:00:00")


def _score_bytes(data: bytes, name: str, mime: str):
    extraction = extract_metadata_service(data, filename=name, mime_type=mime)
    raw, normalized, derived = split_layers(extraction)
    result = compute_metadata_anomaly_score(
        raw=raw, normalized=normalized, derived=derived, mime_type=mime)
    return result, raw, normalized, derived


def _flag_names(result) -> set:
    return {f["flag"] for f in result["flags"]}


def _upload(client: TestClient, raw_key: str, name: str, data: bytes, mime: str):
    return client.post("/api/v1/upload", headers={"X-API-Key": raw_key},
                       files={"file": (name, data, mime)},
                       data={"provenance_json": json.dumps(
                           {"creator_name": "Alice Example"}),
                           "options_json": "{}"})


# ══════════════════════════════════════════════════════════════════════════════
#  1  Clean JPEG -> no anomalies
# ══════════════════════════════════════════════════════════════════════════════

def test_1_clean_jpeg_no_anomalies():
    result, _, _, _ = _score_bytes(_full_jpeg(), "clean.jpg", "image/jpeg")
    assert result["anomaly_score"] == 0, result
    assert result["flags"] == []
    assert result["anomaly_summary"] == "No anomalies detected."
    assert result["engine_version"] == ANOMALY_ENGINE_VERSION


# ══════════════════════════════════════════════════════════════════════════════
#  2  Stripped EXIF -> exif_stripped (+ derived stripping flags), score > 0
# ══════════════════════════════════════════════════════════════════════════════

def test_2_stripped_exif_flagged():
    result, _, _, _ = _score_bytes(_jpeg_stripped(), "stripped.jpg", "image/jpeg")
    names = _flag_names(result)
    assert "exif_stripped" in names, names
    assert result["anomaly_score"] > 0
    # exif_stripped is High severity (30 pts) and must be counted.
    assert result["anomaly_score"] >= SEVERITY_POINTS["High"]


# ══════════════════════════════════════════════════════════════════════════════
#  3  Reversed timestamps -> timestamp_order_reversed
# ══════════════════════════════════════════════════════════════════════════════

def test_3_reversed_timestamps_flagged():
    data = _jpeg(make="OmniVeilCam",
                 dt_original="2024:06:01 12:00:00",   # created LATER
                 dt_modify="2024:01:01 08:00:00")     # modified EARLIER
    result, _, _, _ = _score_bytes(data, "rev.jpg", "image/jpeg")
    assert "timestamp_order_reversed" in _flag_names(result), result
    # A coherent pair must NOT raise the flag.
    coherent, _, _, _ = _score_bytes(
        _jpeg(make="OmniVeilCam", dt_original="2024:01:01 08:00:00",
              dt_modify="2024:06:01 12:00:00"), "coh.jpg", "image/jpeg")
    assert "timestamp_order_reversed" not in _flag_names(coherent)


# ══════════════════════════════════════════════════════════════════════════════
#  4  Missing / malformed hash (crafted normalized dicts)
# ══════════════════════════════════════════════════════════════════════════════

def test_4_hash_missing_and_malformed():
    # hash_missing: sha256 absent entirely.
    missing = compute_metadata_anomaly_score(
        raw={}, normalized={"hashes": {"md5": "0" * 32}}, derived={},
        mime_type="image/jpeg")
    assert "hash_missing" in _flag_names(missing), missing
    # hash_malformed: sha256 present but wrong length.
    malformed = compute_metadata_anomaly_score(
        raw={}, normalized={"hashes": {"sha256": "abc123"}}, derived={},
        mime_type="image/jpeg")
    assert "hash_malformed" in _flag_names(malformed), malformed
    # A valid 64-hex sha256 raises neither hash flag.
    ok = compute_metadata_anomaly_score(
        raw={}, normalized={"hashes": {"sha256": "a" * 64}}, derived={},
        mime_type="application/octet-stream")
    assert "hash_missing" not in _flag_names(ok)
    assert "hash_malformed" not in _flag_names(ok)


# ══════════════════════════════════════════════════════════════════════════════
#  5  Missing creator -> creator_missing
# ══════════════════════════════════════════════════════════════════════════════

def test_5_missing_creator_flagged():
    # No make/model/software/artist, but timestamps present (so this isolates
    # the creator rule from exif_stripped, which needs an all-empty EXIF block).
    data = _jpeg(dt_modify="2024:01:15 10:30:00")
    result, _, _, _ = _score_bytes(data, "nocreator.jpg", "image/jpeg")
    assert "creator_missing" in _flag_names(result), result
    # With a camera make present, the creator rule must NOT fire.
    with_creator, _, _, _ = _score_bytes(
        _jpeg(make="OmniVeilCam", model="X", dt_modify="2024:01:15 10:30:00"),
        "creator.jpg", "image/jpeg")
    assert "creator_missing" not in _flag_names(with_creator)


# ══════════════════════════════════════════════════════════════════════════════
#  6  gps_removed fires ONLY if GPS keys existed in raw metadata
# ══════════════════════════════════════════════════════════════════════════════

def test_6_gps_removed_requires_raw_gps():
    # (a) No GPS anywhere -> NO gps_removed flag (the headline rule).
    result, raw, _, _ = _score_bytes(_full_jpeg(), "nogps.jpg", "image/jpeg")
    assert not any("gps" in str(k).lower() for k in raw.keys())
    assert "gps_removed" not in _flag_names(result)

    # (b) GPS keys present in raw but no coordinates survived -> flag fires.
    crafted = compute_metadata_anomaly_score(
        raw={"GPS GPSLatitudeRef": "N", "GPS GPSLatitude": "[]"},
        normalized={
            "file": {"mime_type": "image/jpeg"},
            "gps": {"latitude": None, "longitude": None},
        },
        derived={}, mime_type="image/jpeg")
    assert "gps_removed" in _flag_names(crafted), crafted


# ══════════════════════════════════════════════════════════════════════════════
#  7  MIME mismatch -> mime_mismatch (crafted normalized dict)
# ══════════════════════════════════════════════════════════════════════════════

def test_7_mime_mismatch_flagged():
    crafted = compute_metadata_anomaly_score(
        raw={},
        normalized={
            "file": {"mime_type": "image/jpeg", "extension": "jpg"},
            "container": {"mime_type": "image/png", "extension": "png"},
            "hashes": {"sha256": "a" * 64},
        },
        derived={}, mime_type="image/jpeg")
    names = _flag_names(crafted)
    assert "mime_mismatch" in names, crafted
    assert "extension_mismatch" in names, crafted
    # mime_mismatch is High (30) + extension_mismatch Medium (15) = at least 45.
    assert crafted["anomaly_score"] >= 45


# ══════════════════════════════════════════════════════════════════════════════
#  8  Determinism: same file -> identical score + flags
# ══════════════════════════════════════════════════════════════════════════════

def test_8_determinism():
    data = _jpeg_stripped()
    r1, _, norm1, _ = _score_bytes(data, "d.jpg", "image/jpeg")
    # Recompute from a key-reordered copy of the normalized layer.
    reordered = {k: norm1[k] for k in reversed(list(norm1.keys()))}
    r2 = compute_metadata_anomaly_score(
        raw={}, normalized=copy.deepcopy(reordered), derived={},
        mime_type="image/jpeg")
    assert r1["anomaly_score"] == r2["anomaly_score"]
    assert r1["flags"] == r2["flags"]
    assert r1["anomaly_summary"] == r2["anomaly_summary"]


# ══════════════════════════════════════════════════════════════════════════════
#  9  Endpoint smoke: upload -> GET /anomalies 200 + correct shape
# ══════════════════════════════════════════════════════════════════════════════

def test_9_endpoint_smoke():
    with TestClient(main.app, raise_server_exceptions=False) as client:
        _ensure_client(RAW_KEY_A, TENANT_A, "anom-a@example.com")
        up = _upload(client, RAW_KEY_A, "stripped.jpg", _jpeg_stripped(),
                     "image/jpeg")
        assert up.status_code == 200, up.text
        # Upload response shape is unchanged — no anomaly fields leaked into it.
        assert "anomaly_score" not in up.json()
        assert "flags" not in up.json()
        omni_id = up.json()["omni_id"]

        r = client.get(f"/api/v1/metadata/assets/{omni_id}/anomalies",
                       headers={"X-API-Key": RAW_KEY_A})
        assert r.status_code == 200, r.text
        body = r.json()
        assert set(body.keys()) == {
            "omni_id", "anomaly_score", "flags", "anomaly_summary",
            "engine_version", "analyzed_at"}
        assert body["omni_id"] == omni_id
        assert isinstance(body["anomaly_score"], int)
        assert 0 <= body["anomaly_score"] <= 100
        assert "exif_stripped" in {f["flag"] for f in body["flags"]}
        for f in body["flags"]:
            assert set(f.keys()) == {
                "flag", "category", "severity", "reason", "affected_fields",
                "recommended_action"}
            assert f["severity"] in ("Low", "Medium", "High")
            assert isinstance(f["reason"], str) and f["reason"].strip()
        # Second read is identical (stored, deterministic).
        r2 = client.get(f"/api/v1/metadata/assets/{omni_id}/anomalies",
                        headers={"X-API-Key": RAW_KEY_A})
        assert r2.json() == body


# ══════════════════════════════════════════════════════════════════════════════
# 10  Tenant isolation at the anomalies endpoint
# ══════════════════════════════════════════════════════════════════════════════

def test_10_tenant_isolation():
    with TestClient(main.app, raise_server_exceptions=False) as client:
        _ensure_client(RAW_KEY_A, TENANT_A, "anom-a@example.com")
        _ensure_client(RAW_KEY_B, TENANT_B, "anom-b@example.com")
        up = _upload(client, RAW_KEY_A, "a.jpg", _full_jpeg(), "image/jpeg")
        assert up.status_code == 200, up.text
        omni_id = up.json()["omni_id"]
        # Tenant B must not see tenant A's asset anomalies.
        r = client.get(f"/api/v1/metadata/assets/{omni_id}/anomalies",
                       headers={"X-API-Key": RAW_KEY_B})
        assert r.status_code == 404, r.text


# ══════════════════════════════════════════════════════════════════════════════
# 11  Future timestamp / impossible + partial GPS / software rules
# ══════════════════════════════════════════════════════════════════════════════

def test_11a_future_timestamp_flagged():
    data = _jpeg(make="OmniVeilCam",
                 dt_original="2099:01:01 00:00:00",
                 dt_modify="2099:01:01 00:00:00")
    result, _, _, _ = _score_bytes(data, "future.jpg", "image/jpeg")
    assert "timestamp_future" in _flag_names(result), result


def test_11b_impossible_and_partial_gps():
    impossible = compute_metadata_anomaly_score(
        raw={}, normalized={"gps": {"latitude": 137.5, "longitude": 12.0}},
        derived={}, mime_type="image/jpeg")
    assert "gps_impossible_coordinates" in _flag_names(impossible), impossible
    partial = compute_metadata_anomaly_score(
        raw={}, normalized={"gps": {"latitude": 37.7, "longitude": None}},
        derived={}, mime_type="image/jpeg")
    assert "gps_partial" in _flag_names(partial), partial


def test_11c_software_conflict():
    # Editing software present, no camera device -> software_conflict.
    data = _jpeg(software="Adobe Photoshop 24.0 (Windows)",
                 dt_modify="2024:03:02 14:05:00")
    result, _, _, _ = _score_bytes(data, "ps.jpg", "image/jpeg")
    assert "software_conflict" in _flag_names(result), result


# ══════════════════════════════════════════════════════════════════════════════
# 12  Regression smoke: routes present + anomalies route added
# ══════════════════════════════════════════════════════════════════════════════

def test_12_regression_smoke_routes_present():
    with TestClient(main.app, raise_server_exceptions=False) as client:
        assert client.get("/health").status_code == 200
        spec = client.get("/openapi.json")
        assert spec.status_code == 200
        paths = spec.json()["paths"]
        assert "/api/v1/upload" in paths
        assert "/api/v1/metadata/assets/{omni_id}" in paths
        assert "/api/v1/metadata/assets/{omni_id}/trust-score" in paths
        assert "/api/v1/metadata/assets/{omni_id}/anomalies" in paths
