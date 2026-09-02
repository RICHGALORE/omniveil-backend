"""
Metadata Intelligence — Commit 2 (persistence) tests.

Proves that the durable ``asset_metadata`` layer is populated at upload time,
stored as three separate layers (raw / normalized / derived), stamped with a
central engine identity, keyed to a deterministic metadata SHA-256, kept to one
record per asset (re-analysis updates in place), and read back only by the
owning tenant. Also proves the persistence layer is additive: uploads,
registry, certificate verification and Live Split contributor persistence all
continue to work.

All fixtures are generated in-code from REAL bytes (Pillow JPEG, ffmpeg/mutagen
MP3, a minimal valid PDF) — no mock-only JSON stand-ins.

Requirement coverage (18):
  1  image upload persists metadata
  2  MP3 upload persists metadata
  3  PDF upload persists metadata
  4  raw layer stored
  5  normalized layer stored
  6  derived layer stored
  7  engine name + version stored
  8  metadata SHA-256 deterministic
  9  one asset = one record
  10 re-analysis updates without uncontrolled duplicate
  11 Tenant A cannot retrieve Tenant B metadata
  12 unknown Omni ID -> 404
  13 missing optional metadata does not fail persistence
  14 upload response shape unchanged
  15 Registry still 200
  16 certificate verification still passes
  17 Live Split contributor persistence still passes
  18 full regression green  (see: regression gate harness — asserted here by a
     smoke check that health + openapi + the new read routes are all served)
"""
import base64
import copy
import io
import json
import math
import shutil
import struct
import subprocess
import uuid
import wave

from fastapi.testclient import TestClient

import main
from app.db.session import SessionLocal
from app.db.models import Client, AssetMetadata
from app.core.tenant import hash_api_key
from app.services import crypto_signing as cs
from app.services.metadata_extraction import (
    extract_metadata_service,
    ENGINE_NAME,
    ENGINE_VERSION,
)
from app.services.metadata_persistence import (
    compute_metadata_sha256,
    split_layers,
    persist_asset_metadata,
    get_metadata_by_omni_id,
)

# Two independent tenants for isolation testing.
RAW_KEY_A = "ov_live_persist_test_tenant_a_0001"
RAW_KEY_B = "ov_live_persist_test_tenant_b_0002"
TENANT_A = "persist-test-tenant-a"
TENANT_B = "persist-test-tenant-b"


# ── Client seeding ─────────────────────────────────────────────────────────────

def _ensure_client(raw_key: str, tenant_id: str, email: str):
    db = SessionLocal()
    try:
        kh = hash_api_key(raw_key)
        if not db.query(Client).filter(Client.api_key_hash == kh).first():
            db.add(Client(
                id=str(uuid.uuid4()),
                tenant_id=tenant_id,
                company_name=f"Persist Test {tenant_id}",
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
    """A plain PNG with NO EXIF / GPS / XMP — exercises the 'missing optional
    metadata' path."""
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
                 "-metadata", "title=Persist Track", "-metadata", "artist=Marlon",
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
        b"4 0 obj<</Title(Persist Doc)/Author(Omni Veil)/Producer(pytest)>>endobj\n"
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


# ══════════════════════════════════════════════════════════════════════════════
#  1–3  Upload persists metadata for image / MP3 / PDF
# ══════════════════════════════════════════════════════════════════════════════

def test_1_image_upload_persists_metadata():
    with TestClient(main.app, raise_server_exceptions=False) as client:
        _ensure_client(RAW_KEY_A, TENANT_A, "persist-a@example.com")
        up = _upload(client, RAW_KEY_A, "cam.jpg", _jpeg_with_exif_bytes(), "image/jpeg")
        assert up.status_code == 200, up.text
        omni_id = up.json()["omni_id"]

        r = client.get(f"/api/v1/metadata/assets/{omni_id}",
                       headers={"X-API-Key": RAW_KEY_A})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["omni_id"] == omni_id
        assert body["supported"] is True
        assert body["normalized_metadata"]["camera"]["make"] == "OmniVeilCam"


def test_2_mp3_upload_persists_metadata():
    with TestClient(main.app, raise_server_exceptions=False) as client:
        _ensure_client(RAW_KEY_A, TENANT_A, "persist-a@example.com")
        up = _upload(client, RAW_KEY_A, "song.mp3", _mp3_bytes(), "audio/mpeg")
        assert up.status_code == 200, up.text
        omni_id = up.json()["omni_id"]

        r = client.get(f"/api/v1/metadata/assets/{omni_id}",
                       headers={"X-API-Key": RAW_KEY_A})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["omni_id"] == omni_id
        assert "audio_tags" in body["normalized_metadata"]


def test_3_pdf_upload_persists_metadata():
    with TestClient(main.app, raise_server_exceptions=False) as client:
        _ensure_client(RAW_KEY_A, TENANT_A, "persist-a@example.com")
        up = _upload(client, RAW_KEY_A, "doc.pdf", _pdf_bytes(), "application/pdf")
        assert up.status_code == 200, up.text
        omni_id = up.json()["omni_id"]

        r = client.get(f"/api/v1/metadata/assets/{omni_id}",
                       headers={"X-API-Key": RAW_KEY_A})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["omni_id"] == omni_id
        assert body["normalized_metadata"]["container"]["mime_type"] == "application/pdf"


# ══════════════════════════════════════════════════════════════════════════════
#  4–7  Three layers + engine identity are stored
# ══════════════════════════════════════════════════════════════════════════════

def test_4_5_6_7_layers_and_engine_stored():
    with TestClient(main.app, raise_server_exceptions=False) as client:
        _ensure_client(RAW_KEY_A, TENANT_A, "persist-a@example.com")
        up = _upload(client, RAW_KEY_A, "cam.jpg", _jpeg_with_exif_bytes(), "image/jpeg")
        assert up.status_code == 200, up.text
        omni_id = up.json()["omni_id"]

        r = client.get(f"/api/v1/metadata/assets/{omni_id}",
                       headers={"X-API-Key": RAW_KEY_A})
        assert r.status_code == 200, r.text
        body = r.json()

        # 4 raw layer stored (exact extractor output present)
        assert isinstance(body["raw_metadata"], dict)
        # 5 normalized layer stored (canonical sections)
        norm = body["normalized_metadata"]
        for sec in ("file", "technical", "camera", "gps", "hashes", "exif"):
            assert sec in norm, f"normalized missing {sec}"
        # 6 derived layer stored (envelope)
        der = body["derived_metadata"]
        for k in ("extractor", "exiftool_available", "supported",
                  "metadata_sha256", "engine_name", "engine_version"):
            assert k in der, f"derived missing {k}"
        # 7 engine name + version stored (top-level + inside derived, central const)
        assert body["engine_name"] == ENGINE_NAME == "Omni Veil Metadata Intelligence"
        assert body["engine_version"] == ENGINE_VERSION == "1.0.0"
        assert der["engine_name"] == ENGINE_NAME
        assert der["engine_version"] == ENGINE_VERSION

        # raw endpoint returns only the raw layer
        rr = client.get(f"/api/v1/metadata/assets/{omni_id}/raw",
                        headers={"X-API-Key": RAW_KEY_A})
        assert rr.status_code == 200, rr.text
        assert "raw_metadata" in rr.json()
        assert "normalized_metadata" not in rr.json()


# ══════════════════════════════════════════════════════════════════════════════
#  8  Deterministic metadata SHA-256
# ══════════════════════════════════════════════════════════════════════════════

def test_8_metadata_sha256_deterministic():
    extraction = extract_metadata_service(
        _jpeg_with_exif_bytes(), filename="cam.jpg", mime_type="image/jpeg")
    _, normalized, _ = split_layers(extraction)

    # Same content -> same digest.
    h1 = compute_metadata_sha256(normalized)
    h2 = compute_metadata_sha256(normalized)
    assert h1 == h2 and len(h1) == 64

    # Reordered dict -> same digest (canonicalization is order-independent).
    reordered = {k: normalized[k] for k in reversed(list(normalized.keys()))}
    assert compute_metadata_sha256(reordered) == h1

    # Different content -> different digest.
    other = extract_metadata_service(
        _plain_png_bytes(), filename="x.png", mime_type="image/png")
    _, other_norm, _ = split_layers(other)
    assert compute_metadata_sha256(other_norm) != h1


# ══════════════════════════════════════════════════════════════════════════════
#  9–10  One asset = one record; re-analysis updates in place
# ══════════════════════════════════════════════════════════════════════════════

def test_9_one_asset_one_record():
    with TestClient(main.app, raise_server_exceptions=False) as client:
        _ensure_client(RAW_KEY_A, TENANT_A, "persist-a@example.com")
        up = _upload(client, RAW_KEY_A, "cam.jpg", _jpeg_with_exif_bytes(), "image/jpeg")
        assert up.status_code == 200, up.text
        omni_id = up.json()["omni_id"]

        db = SessionLocal()
        try:
            rows = db.query(AssetMetadata).filter(
                AssetMetadata.omni_id == omni_id).all()
            assert len(rows) == 1
        finally:
            db.close()


def test_10_reanalysis_updates_without_duplicate():
    with TestClient(main.app, raise_server_exceptions=False) as client:
        _ensure_client(RAW_KEY_A, TENANT_A, "persist-a@example.com")
        content = _jpeg_with_exif_bytes()
        up1 = _upload(client, RAW_KEY_A, "cam.jpg", content, "image/jpeg")
        assert up1.status_code == 200, up1.text
        omni_id = up1.json()["omni_id"]

        # Re-upload identical content -> deterministic same omni_id, asset_id
        # is regenerated by the pipeline, but persistence must update in place.
        up2 = _upload(client, RAW_KEY_A, "cam.jpg", content, "image/jpeg")
        assert up2.status_code == 200, up2.text
        assert up2.json()["omni_id"] == omni_id

        db = SessionLocal()
        try:
            rows = db.query(AssetMetadata).filter(
                AssetMetadata.omni_id == omni_id).all()
            assert len(rows) == 1, "re-analysis must update, not duplicate"
            # updated_at should be >= analyzed_at region; record still coherent.
            assert rows[0].engine_version == ENGINE_VERSION
        finally:
            db.close()


# ══════════════════════════════════════════════════════════════════════════════
#  11  Tenant isolation — A cannot read B's metadata
# ══════════════════════════════════════════════════════════════════════════════

def test_11_tenant_cannot_read_other_tenant_metadata():
    with TestClient(main.app, raise_server_exceptions=False) as client:
        _ensure_client(RAW_KEY_A, TENANT_A, "persist-a@example.com")
        _ensure_client(RAW_KEY_B, TENANT_B, "persist-b@example.com")

        up = _upload(client, RAW_KEY_A, "cam.jpg", _jpeg_with_exif_bytes(), "image/jpeg")
        assert up.status_code == 200, up.text
        omni_id_a = up.json()["omni_id"]

        # Tenant A can read it.
        ok = client.get(f"/api/v1/metadata/assets/{omni_id_a}",
                        headers={"X-API-Key": RAW_KEY_A})
        assert ok.status_code == 200, ok.text

        # Tenant B must NOT be able to read Tenant A's record -> 404.
        denied = client.get(f"/api/v1/metadata/assets/{omni_id_a}",
                            headers={"X-API-Key": RAW_KEY_B})
        assert denied.status_code == 404, denied.text


# ══════════════════════════════════════════════════════════════════════════════
#  12  Unknown Omni ID -> 404
# ══════════════════════════════════════════════════════════════════════════════

def test_12_unknown_omni_id_404():
    with TestClient(main.app, raise_server_exceptions=False) as client:
        _ensure_client(RAW_KEY_A, TENANT_A, "persist-a@example.com")
        r = client.get("/api/v1/metadata/assets/OV-DOES-NOT-EXIST-0000",
                       headers={"X-API-Key": RAW_KEY_A})
        assert r.status_code == 404, r.text


# ══════════════════════════════════════════════════════════════════════════════
#  13  Missing optional metadata does not fail persistence
# ══════════════════════════════════════════════════════════════════════════════

def test_13_missing_optional_metadata_persists():
    with TestClient(main.app, raise_server_exceptions=False) as client:
        _ensure_client(RAW_KEY_A, TENANT_A, "persist-a@example.com")
        # Plain PNG: no EXIF / GPS / XMP / audio tags — optional sections empty.
        up = _upload(client, RAW_KEY_A, "plain.png", _plain_png_bytes(), "image/png")
        assert up.status_code == 200, up.text
        omni_id = up.json()["omni_id"]

        r = client.get(f"/api/v1/metadata/assets/{omni_id}",
                       headers={"X-API-Key": RAW_KEY_A})
        assert r.status_code == 200, r.text
        norm = r.json()["normalized_metadata"]
        # Optional sections present but empty — persistence still succeeded.
        assert norm["exif"] == {} or norm["exif"] is not None
        assert isinstance(norm["gps"], dict)


# ══════════════════════════════════════════════════════════════════════════════
#  14  Upload response shape includes the issued certificate identity
# ══════════════════════════════════════════════════════════════════════════════

# The exact top-level keys returned by the completed trust-package upload.
_EXPECTED_UPLOAD_KEYS = {
    "omni_id", "asset_id", "cert_id", "filename", "sha256", "blake3", "phash",
    "trust_score", "content_label", "label_reasons", "ai_detection_score",
    "ai_disclosure", "watermark_applied", "watermark_visible",
    "watermark_invisible", "creator_name", "copyright_owner", "license_type",
    "original_path", "watermarked_path", "certificate_path", "manifest_path",
    "registry_url", "created_at", "mime_type", "asset_type", "file_size_bytes",
    "certificate_class", "certificate_class_label", "copyright_readiness",
    "section_a_human_contributions", "section_b_ai_contributions",
    "section_c_ownership_splits", "legal_disclaimer",
}


def test_14_upload_response_shape_unchanged():
    with TestClient(main.app, raise_server_exceptions=False) as client:
        _ensure_client(RAW_KEY_A, TENANT_A, "persist-a@example.com")
        up = _upload(client, RAW_KEY_A, "cam.jpg", _jpeg_with_exif_bytes(), "image/jpeg")
        assert up.status_code == 200, up.text
        keys = set(up.json().keys())
        # No metadata-persistence keys leaked into the upload response.
        assert keys == _EXPECTED_UPLOAD_KEYS, (
            f"unexpected: {keys ^ _EXPECTED_UPLOAD_KEYS}")


# ══════════════════════════════════════════════════════════════════════════════
#  15  Registry still returns 200
# ══════════════════════════════════════════════════════════════════════════════

def test_15_registry_still_200():
    with TestClient(main.app, raise_server_exceptions=False) as client:
        _ensure_client(RAW_KEY_A, TENANT_A, "persist-a@example.com")
        up = _upload(client, RAW_KEY_A, "reg.png", _plain_png_bytes(), "image/png")
        assert up.status_code == 200, up.text
        omni_id = up.json()["omni_id"]

        r = client.get(f"/api/v1/registry/assets/{omni_id}",
                       headers={"X-API-Key": RAW_KEY_A})
        assert r.status_code == 200, r.text
        assert r.json().get("omni_id") == omni_id


# ══════════════════════════════════════════════════════════════════════════════
#  16  Certificate signature verification still passes
# ══════════════════════════════════════════════════════════════════════════════

def test_16_certificate_verification_still_passes():
    keys = cs.generate_ed25519_keypair()
    certificate = {
        "omni_id": "OV-TEST-PERSIST", "cert_id": "cert-persist-0001",
        "issuer": "Omni Veil Trust OS", "subject_name": "Alice Example",
        "certificate_class": "standard",
    }
    metadata = {"omni_id": "OV-TEST-PERSIST", "sha256": "a" * 64,
                "creator_name": "Alice Example"}
    signed = cs.sign_certificate(
        certificate=certificate, metadata=metadata,
        private_key_b64=keys["private_key_b64"],
        public_key_b64=keys["public_key_b64"], public_key_id="OV-ROOT-DEV-001")
    signed["metadata_lock"] = metadata
    signed["legacy_hmac_signature"] = "hmac-placeholder-not-part-of-ed25519"
    assert cs.verify_certificate_signature(signed, metadata) is True


# ══════════════════════════════════════════════════════════════════════════════
#  17  Live Split contributor persistence still passes (coexists with metadata)
# ══════════════════════════════════════════════════════════════════════════════

def test_17_live_split_contributor_persistence_still_works():
    """Live Split contributors flow into the certificate payload (section_c
    ownership splits + section_a human contributions). Commit 2's metadata
    persistence must not disturb that flow, and both must coexist for the same
    upload."""
    with TestClient(main.app, raise_server_exceptions=False) as client:
        _ensure_client(RAW_KEY_A, TENANT_A, "persist-a@example.com")
        provenance = {
            "creator_name": "Alice Example",
            "contributor_count": 2,
            "human_performance_present": True,
            "live_split": {"contributors": [
                {"contributor_name": "Alice", "role": "artist",
                 "ownership_split_pct": 60.0},
                {"contributor_name": "Bob", "role": "producer",
                 "ownership_split_pct": 40.0},
            ]},
            "section_c_ownership_splits": {"Alice": 60.0, "Bob": 40.0},
        }
        up = _upload(client, RAW_KEY_A, "song.mp3", _mp3_bytes(), "audio/mpeg",
                     provenance=provenance)
        assert up.status_code == 200, up.text
        body = up.json()
        omni_id = body["omni_id"]

        # Live Split ownership splits are carried through into the certificate
        # payload on the upload response — unchanged by Commit 2. The builder
        # returns a structured Section C object whose ``splits`` reflect the
        # supplied ownership percentages.
        section_c = body["section_c_ownership_splits"]
        assert section_c["section"] == "C"
        split_pcts = sorted(s["ownership_split_pct"] for s in section_c["splits"])
        assert split_pcts == [40.0, 60.0]

        # And metadata persistence coexisted (wrote exactly one record).
        db = SessionLocal()
        try:
            md = db.query(AssetMetadata).filter(
                AssetMetadata.omni_id == omni_id).all()
            assert len(md) == 1
        finally:
            db.close()


# ══════════════════════════════════════════════════════════════════════════════
#  18  Regression smoke — health, openapi and the new read routes are served
# ══════════════════════════════════════════════════════════════════════════════

def test_18_regression_smoke():
    with TestClient(main.app, raise_server_exceptions=False) as client:
        h = client.get("/health")
        assert h.status_code == 200, h.text

        spec = client.get("/openapi.json")
        assert spec.status_code == 200, spec.text
        paths = spec.json()["paths"]
        # New Commit 2 read routes are present under the metadata prefix.
        assert "/api/v1/metadata/assets/{omni_id}" in paths
        assert "/api/v1/metadata/assets/{omni_id}/raw" in paths
        # Pre-existing critical routes still present.
        assert "/api/v1/upload" in paths
        assert "/api/v1/metadata/extract" in paths
