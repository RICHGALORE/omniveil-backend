"""
Tests for the Metadata Intelligence Engine — Commit 1 (extraction service).

Covers the required scenarios: JPEG, PNG, MP3, WAV, PDF, an unsupported file,
missing ExifTool (forced fallback), a corrupt file, and an empty upload. Both
the service function and the temporary ``POST /api/v1/metadata/extract``
endpoint are exercised.

Fixtures are generated in-code so the suite has no binary asset dependencies:
  * PNG / JPEG / TIFF via Pillow
  * WAV via the stdlib ``wave`` module
  * MP3 via ffmpeg when available, otherwise a synthetic MPEG frame
  * PDF via a minimal hand-written PDF byte string
"""
import io
import math
import shutil
import struct
import subprocess
import wave

import pytest
from fastapi.testclient import TestClient

from main import app
from app.services import metadata_extraction as mx
from app.services.metadata_extraction import extract_metadata_service

client = TestClient(app, raise_server_exceptions=False)

CATEGORIES = (
    "file", "technical", "timestamps", "camera",
    "location", "copyright", "software", "hashes", "raw_metadata",
)


# ── Fixture builders ──────────────────────────────────────────────────────────

def _png_bytes() -> bytes:
    from PIL import Image
    buf = io.BytesIO()
    Image.new("RGB", (16, 12), (200, 40, 40)).save(buf, format="PNG")
    return buf.getvalue()


def _jpeg_bytes() -> bytes:
    from PIL import Image
    buf = io.BytesIO()
    Image.new("RGB", (32, 24), (10, 120, 220)).save(buf, format="JPEG", quality=90)
    return buf.getvalue()


def _wav_bytes() -> bytes:
    buf = io.BytesIO()
    with wave.open(buf, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(44100)
        frames = bytearray()
        for i in range(4410):  # 0.1s
            sample = int(32767 * 0.2 * math.sin(2 * math.pi * 440 * i / 44100))
            frames += struct.pack("<h", sample)
        w.writeframes(bytes(frames))
    return buf.getvalue()


def _mp3_bytes() -> bytes:
    if shutil.which("ffmpeg"):
        try:
            proc = subprocess.run(
                ["ffmpeg", "-hide_banner", "-loglevel", "error", "-f", "lavfi",
                 "-i", "sine=frequency=440:duration=0.3", "-ac", "1",
                 "-b:a", "64k", "-f", "mp3", "pipe:1"],
                capture_output=True, timeout=30,
            )
            if proc.returncode == 0 and proc.stdout:
                return proc.stdout
        except Exception:
            pass
    # Fallback: a couple of synthetic MPEG-1 Layer III frame headers so mutagen
    # at least sees an MP3 stream. Not a fully valid file, but exercises the
    # audio path + graceful warnings.
    return b"\xff\xfb\x90\x00" + b"\x00" * 417 + b"\xff\xfb\x90\x00" + b"\x00" * 417


def _pdf_bytes() -> bytes:
    return (
        b"%PDF-1.4\n"
        b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
        b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
        b"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 200 200]>>endobj\n"
        b"4 0 obj<</Title(Test Doc)/Author(Omni Veil)/Producer(pytest)>>endobj\n"
        b"xref\n0 5\n0000000000 65535 f \n"
        b"trailer<</Root 1 0 R/Info 4 0 R/Size 5>>\n"
        b"startxref\n0\n%%EOF\n"
    )


# ── Service-level tests ────────────────────────────────────────────────────────

def _assert_shape(result: dict):
    for cat in CATEGORIES:
        assert cat in result, f"missing category: {cat}"
    assert "duration_ms" in result and isinstance(result["duration_ms"], (int, float))
    assert "extractor" in result
    assert "warnings" in result and isinstance(result["warnings"], list)
    assert result["hashes"]["sha256"]
    assert result["hashes"]["md5"]


def test_jpeg_extraction():
    result = extract_metadata_service(_jpeg_bytes(), filename="photo.jpg",
                                      mime_type="image/jpeg")
    _assert_shape(result)
    assert result["supported"] is True
    assert result["file"]["extension"] == "jpg"
    assert result["file"]["mime_type"] == "image/jpeg"
    assert result["technical"]["resolution"] == "32x24"
    assert result["hashes"]["perceptual_hash"] is not None


def test_png_extraction():
    result = extract_metadata_service(_png_bytes(), filename="image.png",
                                      mime_type="image/png")
    _assert_shape(result)
    assert result["supported"] is True
    assert result["file"]["extension"] == "png"
    assert result["technical"]["resolution"] == "16x12"


def test_mp3_extraction():
    result = extract_metadata_service(_mp3_bytes(), filename="song.mp3",
                                      mime_type="audio/mpeg")
    _assert_shape(result)
    assert result["supported"] is True
    assert result["file"]["extension"] == "mp3"


def test_wav_extraction():
    result = extract_metadata_service(_wav_bytes(), filename="tone.wav",
                                      mime_type="audio/x-wav")
    _assert_shape(result)
    assert result["supported"] is True
    assert result["file"]["extension"] == "wav"
    # sample rate should be discoverable via mutagen
    assert result["technical"]["sample_rate"] in (44100, None)


def test_pdf_extraction():
    result = extract_metadata_service(_pdf_bytes(), filename="doc.pdf",
                                      mime_type="application/pdf")
    _assert_shape(result)
    assert result["supported"] is True
    assert result["file"]["extension"] == "pdf"


def test_unsupported_file():
    result = extract_metadata_service(b"just some plain text", filename="notes.txt",
                                      mime_type="text/plain")
    _assert_shape(result)
    assert result["supported"] is False
    # file-level info + hashes must still be present
    assert result["file"]["size"] == len(b"just some plain text")
    assert any("nsupported" in w.lower() or "file-level" in w.lower()
               for w in result["warnings"])


def test_missing_exiftool_forces_fallback(monkeypatch):
    # Force the "ExifTool not installed" branch regardless of host.
    monkeypatch.setattr(mx, "exiftool_available", lambda: False)
    result = extract_metadata_service(_png_bytes(), filename="image.png",
                                      mime_type="image/png")
    _assert_shape(result)
    assert result["exiftool_available"] is False
    assert result["extractor"] == "python-fallback"
    # extraction must still succeed
    assert result["technical"]["resolution"] == "16x12"


def test_corrupt_file_does_not_raise():
    # Bytes claiming to be a PNG but total garbage.
    corrupt = b"\x89PNG\r\n\x1a\n" + b"\xde\xad\xbe\xef" * 20
    result = extract_metadata_service(corrupt, filename="broken.png",
                                      mime_type="image/png")
    _assert_shape(result)
    # Should not crash; hashes still computed.
    assert result["hashes"]["sha256"]


def test_empty_upload():
    result = extract_metadata_service(b"", filename="empty.jpg",
                                      mime_type="image/jpeg")
    _assert_shape(result)
    assert result["file"]["size"] == 0
    assert any("empty" in w.lower() for w in result["warnings"])


# ── Endpoint-level tests ───────────────────────────────────────────────────────

def test_endpoint_jpeg():
    resp = client.post(
        "/api/v1/metadata/extract",
        files={"file": ("photo.jpg", _jpeg_bytes(), "image/jpeg")},
    )
    assert resp.status_code == 200
    body = resp.json()
    for cat in CATEGORIES:
        assert cat in body
    assert body["file"]["extension"] == "jpg"
    assert body["technical"]["resolution"] == "32x24"


def test_endpoint_pdf():
    resp = client.post(
        "/api/v1/metadata/extract",
        files={"file": ("doc.pdf", _pdf_bytes(), "application/pdf")},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["file"]["extension"] == "pdf"
    assert body["supported"] is True


def test_endpoint_empty_upload():
    resp = client.post(
        "/api/v1/metadata/extract",
        files={"file": ("empty.jpg", b"", "image/jpeg")},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["file"]["size"] == 0
    assert any("empty" in w.lower() for w in body["warnings"])
