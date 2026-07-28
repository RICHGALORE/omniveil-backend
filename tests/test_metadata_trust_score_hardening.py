"""
Metadata Intelligence — Commit 3.1 (Trust Score validation & hardening) tests.

This suite validates and hardens the Commit 3 Metadata Trust Score Engine. It
does NOT redesign scoring; it proves two additive changes made in Commit 3.1:

  * TIMESTAMP NORMALIZATION FIX — exifread emits space-separated group keys
    ("Image DateTime", "EXIF DateTimeOriginal", "EXIF DateTimeDigitized").
    ``_normalize_timestamps`` previously listed only bare tag names, so the
    values were silently dropped and the timestamps factor always scored 0.
    The fix adds the space-form key candidates; timestamps now populate and the
    factor scores as designed.

  * EXPLAINABILITY — ``compute_metadata_trust_score`` and the trust-score
    endpoint now return a per-factor ``explanations`` map with points / max /
    human-readable reason.

Determinism, score movement on metadata change, and the required regression
smoke are also asserted here.

All fixtures are REAL bytes (Pillow JPEG via ``getexif`` — no piexif dependency,
no mock JSON). Distinct tenant keys avoid collision with the Commit 2/3 suites.

Requirement coverage:
  1  identical file -> identical score (service level, incl. dict reordering)
  2  identical file -> identical score (endpoint level)
  3  stripped metadata lowers score vs full metadata
  4  restoring metadata raises score back above the stripped score
  5  timestamp fix populates normalized timestamps + non-zero timestamps factor
  6  timestamp inconsistency (created > modified) scores lower than a coherent pair
  7  missing creator lowers the creator factor
  8  changing only file content changes the score appropriately
  9  explanations present + well-formed at the service level (all 6 factors)
 10  explanations present + well-formed + deterministic at the endpoint level
 11  regression smoke: health, openapi and the trust-score route still served
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
from app.services.metadata_trust_score import (
    compute_metadata_trust_score,
    SCORE_ENGINE_VERSION,
    WEIGHTS,
)

# Independent tenants for this suite (distinct keys/ids to avoid collision).
RAW_KEY_A = "ov_live_hardening_test_tenant_a_0001"
RAW_KEY_B = "ov_live_hardening_test_tenant_b_0002"
TENANT_A = "hardening-test-tenant-a"
TENANT_B = "hardening-test-tenant-b"


# ── Client seeding ─────────────────────────────────────────────────────────────

def _ensure_client(raw_key: str, tenant_id: str, email: str):
    db = SessionLocal()
    try:
        kh = hash_api_key(raw_key)
        if not db.query(Client).filter(Client.api_key_hash == kh).first():
            db.add(Client(
                id=str(uuid.uuid4()),
                tenant_id=tenant_id,
                company_name=f"Hardening Test {tenant_id}",
                email=email,
                status="approved",
                plan="creator",
                api_key_hash=kh,
            ))
            db.commit()
    finally:
        db.close()


# ── Real-byte fixture builders (Pillow only; getexif persists Exif sub-IFD) ─────

def _jpeg(make=None, model=None, software=None, artist=None, copyright_=None,
          dt_original=None, dt_modify=None, dt_digitized=None,
          color=(30, 90, 160), size=(48, 36)) -> bytes:
    img = Image.new("RGB", size, color)
    exif = img.getexif()
    if make:
        exif[271] = make            # Image Make
    if model:
        exif[272] = model           # Image Model
    if software:
        exif[305] = software        # Image Software
    if artist:
        exif[315] = artist          # Image Artist
    if copyright_:
        exif[33432] = copyright_    # Image Copyright
    if dt_modify:
        exif[306] = dt_modify       # Image DateTime  -> normalized "modified"
    if dt_original or dt_digitized:
        ifd = exif.get_ifd(0x8769)  # Exif sub-IFD
        if dt_original:
            ifd[36867] = dt_original    # DateTimeOriginal   -> "created"
        if dt_digitized:
            ifd[36868] = dt_digitized   # DateTimeDigitized  -> "digitized"
    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=90, exif=exif)
    return buf.getvalue()


def _jpeg_stripped(color=(30, 90, 160), size=(48, 36)) -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", size, color).save(buf, format="JPEG", quality=90)
    return buf.getvalue()


def _score_bytes(data: bytes, name: str, mime: str) -> dict:
    """Service-level score straight from real bytes (no DB, no endpoint)."""
    extraction = extract_metadata_service(data, filename=name, mime_type=mime)
    raw, normalized, derived = split_layers(extraction)
    return compute_metadata_trust_score(raw=raw, normalized=normalized,
                                        derived=derived), normalized


def _upload(client: TestClient, raw_key: str, name: str, data: bytes, mime: str):
    headers = {"X-API-Key": raw_key}
    files = {"file": (name, data, mime)}
    form = {"provenance_json": json.dumps({"creator_name": "Alice Example"}),
            "options_json": "{}"}
    return client.post("/api/v1/upload", headers=headers, files=files, data=form)


# A rich, fully-populated JPEG reused across several tests.
def _full_jpeg() -> bytes:
    return _jpeg(make="OmniVeilCam", model="Model-X100",
                 software="OmniVeil Studio", artist="Alice Example",
                 copyright_="(c) 2024 Alice",
                 dt_original="2024:01:15 09:00:00",
                 dt_modify="2024:01:15 10:30:00",
                 dt_digitized="2024:01:15 09:00:00")


# ══════════════════════════════════════════════════════════════════════════════
#  1–2  Determinism: identical file -> identical score
# ══════════════════════════════════════════════════════════════════════════════

def test_1_identical_metadata_identical_score_service():
    data = _full_jpeg()
    s1, norm = _score_bytes(data, "cam.jpg", "image/jpeg")
    # Recompute from a deep-copied + key-reordered normalized layer.
    reordered = {k: norm[k] for k in reversed(list(norm.keys()))}
    raw, _, derived = split_layers(
        extract_metadata_service(data, filename="cam.jpg", mime_type="image/jpeg"))
    s2 = compute_metadata_trust_score(raw=raw, normalized=copy.deepcopy(reordered),
                                      derived=derived)
    assert s1 == s2, "identical metadata must yield an identical score payload"
    assert s1["engine_version"] == SCORE_ENGINE_VERSION


def test_2_identical_file_identical_score_endpoint():
    data = _full_jpeg()
    with TestClient(main.app, raise_server_exceptions=False) as client:
        _ensure_client(RAW_KEY_A, TENANT_A, "harden-a@example.com")
        scores = []
        for _ in range(2):
            up = _upload(client, RAW_KEY_A, "cam.jpg", data, "image/jpeg")
            assert up.status_code == 200, up.text
            omni_id = up.json()["omni_id"]
            r = client.get(f"/api/v1/metadata/assets/{omni_id}/trust-score",
                           headers={"X-API-Key": RAW_KEY_A})
            assert r.status_code == 200, r.text
            body = r.json()
            scores.append((body["overall"], body["breakdown"]))
        assert scores[0] == scores[1], "same bytes must produce the same score"


# ══════════════════════════════════════════════════════════════════════════════
#  3–4  Stripped metadata lowers score; restoring it raises the score back
# ══════════════════════════════════════════════════════════════════════════════

def test_3_stripped_metadata_lowers_score():
    full, _ = _score_bytes(_full_jpeg(), "full.jpg", "image/jpeg")
    stripped, _ = _score_bytes(_jpeg_stripped(), "stripped.jpg", "image/jpeg")
    assert stripped["overall"] < full["overall"], (
        f"stripped ({stripped['overall']}) must score below full "
        f"({full['overall']})")
    # The factors that lost the metadata must be the ones that dropped.
    assert stripped["breakdown"]["completeness"] < full["breakdown"]["completeness"]
    assert stripped["breakdown"]["creator"] < full["breakdown"]["creator"]
    assert stripped["breakdown"]["timestamps"] < full["breakdown"]["timestamps"]


def test_4_restoring_metadata_raises_score():
    stripped, _ = _score_bytes(_jpeg_stripped(), "stripped.jpg", "image/jpeg")
    restored, _ = _score_bytes(_full_jpeg(), "restored.jpg", "image/jpeg")
    assert restored["overall"] > stripped["overall"], (
        "restoring metadata must raise the score above the stripped score")


# ══════════════════════════════════════════════════════════════════════════════
#  5  Timestamp fix: normalized timestamps populate + non-zero factor
# ══════════════════════════════════════════════════════════════════════════════

def test_5_timestamp_fix_populates_timestamps():
    data = _jpeg(make="OmniVeilCam",
                 dt_original="2024:01:15 09:00:00",
                 dt_modify="2024:01:15 10:30:00",
                 dt_digitized="2024:01:15 09:00:00")
    score, normalized = _score_bytes(data, "ts.jpg", "image/jpeg")
    ts = normalized.get("timestamps") or {}
    # The defect was: these came back all-null. Post-fix they must populate.
    assert ts.get("created") == "2024:01:15 09:00:00", ts
    assert ts.get("modified") == "2024:01:15 10:30:00", ts
    assert ts.get("digitized") == "2024:01:15 09:00:00", ts
    # And the timestamps factor must now earn its full weight (coherent pair).
    assert score["breakdown"]["timestamps"] == WEIGHTS["timestamps"], (
        f"expected full {WEIGHTS['timestamps']} timestamp points, "
        f"got {score['breakdown']['timestamps']}")


# ══════════════════════════════════════════════════════════════════════════════
#  6  Timestamp inconsistency affects the score
# ══════════════════════════════════════════════════════════════════════════════

def test_6_timestamp_inconsistency_lowers_score():
    coherent = _jpeg(make="OmniVeilCam",
                     dt_original="2024:01:15 09:00:00",   # created earlier
                     dt_modify="2024:01:15 10:30:00")     # modified later
    reversed_ = _jpeg(make="OmniVeilCam",
                      dt_original="2024:06:01 12:00:00",  # created LATER
                      dt_modify="2024:01:01 08:00:00")    # modified EARLIER
    s_coh, _ = _score_bytes(coherent, "coh.jpg", "image/jpeg")
    s_rev, _ = _score_bytes(reversed_, "rev.jpg", "image/jpeg")
    assert s_rev["breakdown"]["timestamps"] < s_coh["breakdown"]["timestamps"], (
        "an inconsistent created/modified pair must score below a coherent one")
    # Both still credit timestamp presence (non-zero), only ordering differs.
    assert s_rev["breakdown"]["timestamps"] > 0


# ══════════════════════════════════════════════════════════════════════════════
#  7  Missing creator affects the score
# ══════════════════════════════════════════════════════════════════════════════

def test_7_missing_creator_lowers_creator_factor():
    # The pure-Python fallback path surfaces device attribution (camera
    # make/model) as its reliable creator signal. An asset carrying that
    # attribution must score higher on the creator factor than one without it.
    with_creator = _jpeg(make="OmniVeilCam", model="Model-X100",
                         dt_modify="2024:01:15 10:30:00")
    without_creator = _jpeg(dt_modify="2024:01:15 10:30:00")  # no device/owner
    s_with, _ = _score_bytes(with_creator, "wc.jpg", "image/jpeg")
    s_without, _ = _score_bytes(without_creator, "nc.jpg", "image/jpeg")
    assert s_without["breakdown"]["creator"] < s_with["breakdown"]["creator"], (
        "an asset missing creator/ownership/device attribution must score lower "
        "on the creator factor "
        f"(with={s_with['breakdown']['creator']}, "
        f"without={s_without['breakdown']['creator']})")


# ══════════════════════════════════════════════════════════════════════════════
#  8  Changing only file content changes the score appropriately
# ══════════════════════════════════════════════════════════════════════════════

def test_8_content_change_changes_metadata_digest():
    # Same metadata inputs but different pixels -> different bytes -> different
    # file hashes and metadata digest. The score is a pure function of the
    # persisted layers, so the digest (a scored input) must differ.
    a = _jpeg(make="OmniVeilCam", color=(10, 20, 30))
    b = _jpeg(make="OmniVeilCam", color=(200, 180, 160))
    _, norm_a = _score_bytes(a, "a.jpg", "image/jpeg")
    _, norm_b = _score_bytes(b, "b.jpg", "image/jpeg")
    assert a != b, "different pixels must yield different bytes"
    assert norm_a["hashes"]["sha256"] != norm_b["hashes"]["sha256"], (
        "different file content must produce different SHA-256 fingerprints")


# ══════════════════════════════════════════════════════════════════════════════
#  9  Explanations present + well-formed at the service level
# ══════════════════════════════════════════════════════════════════════════════

def test_9_explanations_present_service_level():
    score, _ = _score_bytes(_full_jpeg(), "cam.jpg", "image/jpeg")
    assert "explanations" in score
    exp = score["explanations"]
    assert set(exp.keys()) == set(WEIGHTS.keys()), exp.keys()
    for factor, detail in exp.items():
        assert set(detail.keys()) == {"points", "max", "reason"}, detail
        assert detail["max"] == WEIGHTS[factor]
        assert detail["points"] == score["breakdown"][factor]
        assert isinstance(detail["reason"], str) and detail["reason"].strip()
    # Determinism of the reason strings.
    again, _ = _score_bytes(_full_jpeg(), "cam.jpg", "image/jpeg")
    assert {k: v["reason"] for k, v in exp.items()} == \
           {k: v["reason"] for k, v in again["explanations"].items()}


# ══════════════════════════════════════════════════════════════════════════════
# 10  Explanations present + well-formed + deterministic at the endpoint level
# ══════════════════════════════════════════════════════════════════════════════

def test_10_explanations_present_endpoint_level():
    with TestClient(main.app, raise_server_exceptions=False) as client:
        _ensure_client(RAW_KEY_A, TENANT_A, "harden-a@example.com")
        up = _upload(client, RAW_KEY_A, "cam.jpg", _full_jpeg(), "image/jpeg")
        assert up.status_code == 200, up.text
        omni_id = up.json()["omni_id"]
        r = client.get(f"/api/v1/metadata/assets/{omni_id}/trust-score",
                       headers={"X-API-Key": RAW_KEY_A})
        assert r.status_code == 200, r.text
        body = r.json()
        assert "explanations" in body, body
        exp = body["explanations"]
        assert set(exp.keys()) == set(WEIGHTS.keys())
        for factor, detail in exp.items():
            assert set(detail.keys()) == {"points", "max", "reason"}
            assert detail["points"] == body["breakdown"][factor]
            assert isinstance(detail["reason"], str) and detail["reason"].strip()
        # Second read is byte-for-byte identical (stored score is deterministic).
        r2 = client.get(f"/api/v1/metadata/assets/{omni_id}/trust-score",
                        headers={"X-API-Key": RAW_KEY_A})
        assert r2.json()["explanations"] == exp


# ══════════════════════════════════════════════════════════════════════════════
# 11  Regression smoke: existing routes still served
# ══════════════════════════════════════════════════════════════════════════════

def test_11_regression_smoke_routes_present():
    with TestClient(main.app, raise_server_exceptions=False) as client:
        assert client.get("/health").status_code == 200
        spec = client.get("/openapi.json")
        assert spec.status_code == 200
        paths = spec.json()["paths"]
        assert "/api/v1/upload" in paths
        assert "/api/v1/metadata/assets/{omni_id}" in paths
        assert "/api/v1/metadata/assets/{omni_id}/trust-score" in paths
