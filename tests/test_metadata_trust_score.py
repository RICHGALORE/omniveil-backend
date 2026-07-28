"""
Metadata Intelligence — Commit 3 (Metadata Trust Score Engine) tests.

Proves that a deterministic 0–100 metadata trust score is:
  * generated for JPEG / MP3 / PDF uploads and served by the read endpoint,
  * computed PURELY from the persisted metadata layers (no re-reading bytes),
  * identical for identical metadata (headline determinism property),
  * changed when the metadata changes,
  * lowered when metadata is missing / sparse,
  * produced safely for unsupported / junk input (never raises),
  * tenant-isolated at the endpoint,
  * internally coherent (sum(breakdown) == overall; all six factor keys),
  * additive (existing persistence/read routes unaffected).

All fixtures are generated in-code from REAL bytes (Pillow JPEG/PNG,
ffmpeg/synthetic MP3, a minimal valid PDF) — no mock-only JSON stand-ins.

Requirement coverage:
  1  JPEG upload -> trust score generated + served
  2  MP3  upload -> trust score generated + served
  3  PDF  upload -> trust score generated + served
  4  same metadata -> identical score (determinism, incl. dict reordering)
  5  modified metadata -> score changes
  6  missing metadata -> lower score than a rich asset
  7  unsupported / junk metadata handled safely (0–100, no raise)
  8  response contract: overall/breakdown/engine_version/analyzed_at, sums, keys
  9  tenant isolation at the trust-score endpoint (404 across tenants)
 10  breakdown factor points never exceed their configured weights
"""
import copy
import io
import json
import shutil
import subprocess
import uuid

from fastapi.testclient import TestClient

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

# Independent tenants for this suite (distinct keys/ids to avoid collision with
# the Commit 2 persistence suite).
RAW_KEY_A = "ov_live_trustscore_test_tenant_a_0001"
RAW_KEY_B = "ov_live_trustscore_test_tenant_b_0002"
TENANT_A = "trustscore-test-tenant-a"
TENANT_B = "trustscore-test-tenant-b"


# ── Client seeding ─────────────────────────────────────────────────────────────

def _ensure_client(raw_key: str, tenant_id: str, email: str):
    db = SessionLocal()
    try:
        kh = hash_api_key(raw_key)
        if not db.query(Client).filter(Client.api_key_hash == kh).first():
            db.add(Client(
                id=str(uuid.uuid4()),
                tenant_id=tenant_id,
                company_name=f"TrustScore Test {tenant_id}",
                email=email,
                status="approved",
                plan="creator",
                api_key_hash=kh,
            ))
            db.commit()
    finally:
        db.close()


# ── Real-byte fixture builders ──────────────────────────────────────────────────

def _jpeg_with_exif_bytes() -> bytes:
    from PIL import Image
    img = Image.new("RGB", (48, 36), (30, 90, 160))
    exif = img.getexif()
    exif[271] = "OmniVeilCam"      # Make
    exif[272] = "Model-X100"       # Model
    exif[305] = "OmniVeil Studio"  # Software
    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=90, exif=exif)
    return buf.getvalue()


def _plain_png_bytes() -> bytes:
    """A plain PNG with NO EXIF / GPS / XMP — the 'missing metadata' case."""
    from PIL import Image
    buf = io.BytesIO()
    Image.new("RGB", (16, 12), (200, 40, 40)).save(buf, format="PNG")
    return buf.getvalue()


def _mp3_bytes() -> bytes:
    if shutil.which("ffmpeg"):
        try:
            proc = subprocess.run(
                ["ffmpeg", "-hide_banner", "-loglevel", "error", "-f", "lavfi",
                 "-i", "sine=frequency=440:duration=0.3", "-ac", "1", "-b:a", "64k",
                 "-metadata", "title=Trust Track", "-metadata", "artist=Marlon",
                 "-metadata", "album=Omni Veil", "-f", "mp3", "pipe:1"],
                capture_output=True, timeout=30,
            )
            if proc.returncode == 0 and proc.stdout:
                return proc.stdout
        except Exception:
            pass
    return b"\xff\xfb\x90\x00" + b"\x00" * 417 + b"\xff\xfb\x90\x00" + b"\x00" * 417


def _pdf_bytes() -> bytes:
    return (
        b"%PDF-1.4\n"
        b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
        b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
        b"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 200 200]>>endobj\n"
        b"4 0 obj<</Title(Trust Doc)/Author(Omni Veil)/Producer(pytest)>>endobj\n"
        b"xref\n0 5\n0000000000 65535 f \n"
        b"trailer<</Root 1 0 R/Info 4 0 R/Size 5>>\n"
        b"startxref\n0\n%%EOF\n"
    )


def _upload(client: TestClient, raw_key: str, name: str, data: bytes,
            mime: str, provenance: dict | None = None):
    headers = {"X-API-Key": raw_key}
    files = {"file": (name, data, mime)}
    form = {
        "provenance_json": json.dumps(provenance or {"creator_name": "Alice Example"}),
        "options_json": "{}",
    }
    return client.post("/api/v1/upload", headers=headers, files=files, data=form)


def _assert_valid_score_payload(body: dict, omni_id: str):
    """Shared contract assertions for a trust-score endpoint response."""
    assert body["omni_id"] == omni_id
    assert isinstance(body["overall"], int)
    assert 0 <= body["overall"] <= 100
    assert body["engine_version"] == SCORE_ENGINE_VERSION == "1.0.0"
    assert body["analyzed_at"] is not None
    breakdown = body["breakdown"]
    assert set(breakdown.keys()) == set(WEIGHTS.keys())
    # Overall is exactly the sum of the per-factor points.
    assert sum(breakdown.values()) == body["overall"]
    # No factor may exceed its configured weight.
    for factor, pts in breakdown.items():
        assert 0 <= pts <= WEIGHTS[factor], f"{factor}={pts} > {WEIGHTS[factor]}"


# ══════════════════════════════════════════════════════════════════════════════
#  1–3  JPEG / MP3 / PDF uploads generate + serve a trust score
# ══════════════════════════════════════════════════════════════════════════════

def test_1_jpeg_trust_score_generated():
    with TestClient(main.app, raise_server_exceptions=False) as client:
        _ensure_client(RAW_KEY_A, TENANT_A, "trust-a@example.com")
        up = _upload(client, RAW_KEY_A, "cam.jpg", _jpeg_with_exif_bytes(), "image/jpeg")
        assert up.status_code == 200, up.text
        omni_id = up.json()["omni_id"]

        r = client.get(f"/api/v1/metadata/assets/{omni_id}/trust-score",
                       headers={"X-API-Key": RAW_KEY_A})
        assert r.status_code == 200, r.text
        _assert_valid_score_payload(r.json(), omni_id)


def test_2_mp3_trust_score_generated():
    with TestClient(main.app, raise_server_exceptions=False) as client:
        _ensure_client(RAW_KEY_A, TENANT_A, "trust-a@example.com")
        up = _upload(client, RAW_KEY_A, "song.mp3", _mp3_bytes(), "audio/mpeg")
        assert up.status_code == 200, up.text
        omni_id = up.json()["omni_id"]

        r = client.get(f"/api/v1/metadata/assets/{omni_id}/trust-score",
                       headers={"X-API-Key": RAW_KEY_A})
        assert r.status_code == 200, r.text
        _assert_valid_score_payload(r.json(), omni_id)


def test_3_pdf_trust_score_generated():
    with TestClient(main.app, raise_server_exceptions=False) as client:
        _ensure_client(RAW_KEY_A, TENANT_A, "trust-a@example.com")
        up = _upload(client, RAW_KEY_A, "doc.pdf", _pdf_bytes(), "application/pdf")
        assert up.status_code == 200, up.text
        omni_id = up.json()["omni_id"]

        r = client.get(f"/api/v1/metadata/assets/{omni_id}/trust-score",
                       headers={"X-API-Key": RAW_KEY_A})
        assert r.status_code == 200, r.text
        _assert_valid_score_payload(r.json(), omni_id)


# ══════════════════════════════════════════════════════════════════════════════
#  4  Same metadata -> identical score (determinism)
# ══════════════════════════════════════════════════════════════════════════════

def test_4_same_metadata_identical_score():
    extraction = extract_metadata_service(
        _jpeg_with_exif_bytes(), filename="cam.jpg", mime_type="image/jpeg")
    raw, normalized, derived = split_layers(extraction)

    s1 = compute_metadata_trust_score(raw=raw, normalized=normalized, derived=derived)
    s2 = compute_metadata_trust_score(raw=raw, normalized=normalized, derived=derived)
    assert s1 == s2
    assert s1["engine_version"] == "1.0.0"

    # Reordering dict keys must not change the score (order-independent).
    reordered = {k: normalized[k] for k in reversed(list(normalized.keys()))}
    s3 = compute_metadata_trust_score(raw=raw, normalized=reordered, derived=derived)
    assert s3 == s1


def test_4b_same_metadata_identical_score_endpoint():
    """Determinism proven through the persisted/served path: same content
    uploaded twice yields the same omni_id and the same served score."""
    with TestClient(main.app, raise_server_exceptions=False) as client:
        _ensure_client(RAW_KEY_A, TENANT_A, "trust-a@example.com")
        content = _jpeg_with_exif_bytes()

        up1 = _upload(client, RAW_KEY_A, "cam.jpg", content, "image/jpeg")
        assert up1.status_code == 200, up1.text
        omni_id = up1.json()["omni_id"]
        r1 = client.get(f"/api/v1/metadata/assets/{omni_id}/trust-score",
                        headers={"X-API-Key": RAW_KEY_A})
        assert r1.status_code == 200, r1.text

        # Re-upload identical content (same omni_id, re-analysis in place).
        up2 = _upload(client, RAW_KEY_A, "cam.jpg", content, "image/jpeg")
        assert up2.status_code == 200, up2.text
        assert up2.json()["omni_id"] == omni_id
        r2 = client.get(f"/api/v1/metadata/assets/{omni_id}/trust-score",
                        headers={"X-API-Key": RAW_KEY_A})
        assert r2.status_code == 200, r2.text

        assert r1.json()["overall"] == r2.json()["overall"]
        assert r1.json()["breakdown"] == r2.json()["breakdown"]


# ══════════════════════════════════════════════════════════════════════════════
#  5  Modified metadata -> score changes
# ══════════════════════════════════════════════════════════════════════════════

def test_5_modified_metadata_changes_score():
    extraction = extract_metadata_service(
        _jpeg_with_exif_bytes(), filename="cam.jpg", mime_type="image/jpeg")
    raw, normalized, derived = split_layers(extraction)
    base = compute_metadata_trust_score(raw=raw, normalized=normalized, derived=derived)

    # Strip creator/camera/software attribution + hashes -> must lower the score.
    mutated = copy.deepcopy(normalized)
    for section in ("camera", "software", "copyright", "exif", "hashes"):
        if section in mutated:
            mutated[section] = {}
    mutated_derived = copy.deepcopy(derived)
    mutated_derived["metadata_sha256"] = None
    changed = compute_metadata_trust_score(
        raw=raw, normalized=mutated, derived=mutated_derived)

    assert changed["overall"] != base["overall"]
    assert changed["overall"] < base["overall"]


# ══════════════════════════════════════════════════════════════════════════════
#  6  Missing metadata -> lower score than a rich asset
# ══════════════════════════════════════════════════════════════════════════════

def test_6_missing_metadata_lowers_score():
    rich = extract_metadata_service(
        _jpeg_with_exif_bytes(), filename="cam.jpg", mime_type="image/jpeg")
    r_raw, r_norm, r_der = split_layers(rich)
    rich_score = compute_metadata_trust_score(raw=r_raw, normalized=r_norm, derived=r_der)

    sparse = extract_metadata_service(
        _plain_png_bytes(), filename="plain.png", mime_type="image/png")
    s_raw, s_norm, s_der = split_layers(sparse)
    sparse_score = compute_metadata_trust_score(raw=s_raw, normalized=s_norm, derived=s_der)

    assert sparse_score["overall"] < rich_score["overall"]


def test_6b_missing_metadata_lowers_score_endpoint():
    with TestClient(main.app, raise_server_exceptions=False) as client:
        _ensure_client(RAW_KEY_A, TENANT_A, "trust-a@example.com")

        up_rich = _upload(client, RAW_KEY_A, "cam.jpg",
                          _jpeg_with_exif_bytes(), "image/jpeg")
        assert up_rich.status_code == 200, up_rich.text
        rich_id = up_rich.json()["omni_id"]

        up_sparse = _upload(client, RAW_KEY_A, "plain.png",
                            _plain_png_bytes(), "image/png")
        assert up_sparse.status_code == 200, up_sparse.text
        sparse_id = up_sparse.json()["omni_id"]

        rich = client.get(f"/api/v1/metadata/assets/{rich_id}/trust-score",
                          headers={"X-API-Key": RAW_KEY_A}).json()
        sparse = client.get(f"/api/v1/metadata/assets/{sparse_id}/trust-score",
                            headers={"X-API-Key": RAW_KEY_A}).json()
        assert sparse["overall"] < rich["overall"]


# ══════════════════════════════════════════════════════════════════════════════
#  7  Unsupported / junk metadata handled safely (0–100, no raise)
# ══════════════════════════════════════════════════════════════════════════════

def test_7_unsupported_metadata_handled_safely():
    # Junk / unsupported input: extraction never raises, and scoring must not
    # either — it degrades to a low-but-valid score.
    extraction = extract_metadata_service(
        b"this is just plain text, not a real media container",
        filename="notes.txt", mime_type="text/plain")
    raw, normalized, derived = split_layers(extraction)
    score = compute_metadata_trust_score(raw=raw, normalized=normalized, derived=derived)
    assert 0 <= score["overall"] <= 100
    assert set(score["breakdown"].keys()) == set(WEIGHTS.keys())
    assert sum(score["breakdown"].values()) == score["overall"]


def test_7b_empty_inputs_handled_safely():
    # Completely empty layers must not raise and must produce a valid payload.
    score = compute_metadata_trust_score(raw={}, normalized={}, derived={})
    assert 0 <= score["overall"] <= 100
    assert set(score["breakdown"].keys()) == set(WEIGHTS.keys())

    # Even None inputs are tolerated.
    score_none = compute_metadata_trust_score()
    assert 0 <= score_none["overall"] <= 100


# ══════════════════════════════════════════════════════════════════════════════
#  8  Weight ceiling — engine can never award more than the total weight
# ══════════════════════════════════════════════════════════════════════════════

def test_8_weights_sum_to_100_and_ceiling_respected():
    assert sum(WEIGHTS.values()) == 100
    extraction = extract_metadata_service(
        _jpeg_with_exif_bytes(), filename="cam.jpg", mime_type="image/jpeg")
    raw, normalized, derived = split_layers(extraction)
    score = compute_metadata_trust_score(raw=raw, normalized=normalized, derived=derived)
    for factor, pts in score["breakdown"].items():
        assert 0 <= pts <= WEIGHTS[factor]
    assert score["overall"] <= 100


# ══════════════════════════════════════════════════════════════════════════════
#  9  Tenant isolation at the trust-score endpoint
# ══════════════════════════════════════════════════════════════════════════════

def test_9_trust_score_tenant_isolation():
    with TestClient(main.app, raise_server_exceptions=False) as client:
        _ensure_client(RAW_KEY_A, TENANT_A, "trust-a@example.com")
        _ensure_client(RAW_KEY_B, TENANT_B, "trust-b@example.com")

        up = _upload(client, RAW_KEY_A, "cam.jpg", _jpeg_with_exif_bytes(), "image/jpeg")
        assert up.status_code == 200, up.text
        omni_id = up.json()["omni_id"]

        # Owner can read the score.
        ok = client.get(f"/api/v1/metadata/assets/{omni_id}/trust-score",
                        headers={"X-API-Key": RAW_KEY_A})
        assert ok.status_code == 200, ok.text

        # Other tenant must be denied (404, never disclosed).
        denied = client.get(f"/api/v1/metadata/assets/{omni_id}/trust-score",
                            headers={"X-API-Key": RAW_KEY_B})
        assert denied.status_code == 404, denied.text


def test_9b_unknown_omni_id_404():
    with TestClient(main.app, raise_server_exceptions=False) as client:
        _ensure_client(RAW_KEY_A, TENANT_A, "trust-a@example.com")
        r = client.get("/api/v1/metadata/assets/OV-NO-SUCH-ASSET-0000/trust-score",
                       headers={"X-API-Key": RAW_KEY_A})
        assert r.status_code == 404, r.text


# ══════════════════════════════════════════════════════════════════════════════
# 10  Regression smoke — the new route is served alongside existing routes
# ══════════════════════════════════════════════════════════════════════════════

def test_10_regression_smoke_routes_present():
    with TestClient(main.app, raise_server_exceptions=False) as client:
        spec = client.get("/openapi.json")
        assert spec.status_code == 200, spec.text
        paths = spec.json()["paths"]
        # New Commit 3 route present.
        assert "/api/v1/metadata/assets/{omni_id}/trust-score" in paths
        # Pre-existing Commit 1 + Commit 2 routes still present.
        assert "/api/v1/metadata/extract" in paths
        assert "/api/v1/metadata/assets/{omni_id}" in paths
        assert "/api/v1/metadata/assets/{omni_id}/raw" in paths
        assert "/api/v1/upload" in paths
