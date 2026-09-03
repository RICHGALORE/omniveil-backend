from pathlib import Path
from types import SimpleNamespace

from app.api.v1.endpoints import c2pa, certificate_verify, spectra
from app.core.storage import ensure_upload_layout, resolve_stored_path, upload_root
from app.services import export_package


def test_upload_root_honors_absolute_environment_path(monkeypatch, tmp_path):
    root = tmp_path / "render-disk"
    monkeypatch.setenv("UPLOAD_DIR", str(root))

    assert upload_root() == root.resolve()

    layout = ensure_upload_layout()
    assert layout["root"] == root.resolve()
    for name in ("originals", "watermarked", "certificates", "manifests"):
        assert layout[name].is_dir()
        assert layout[name].parent == root.resolve()


def test_relative_upload_root_resolves_from_working_directory(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("UPLOAD_DIR", "uploads")

    assert upload_root() == (tmp_path / "uploads").resolve()


def test_legacy_upload_path_remaps_to_active_persistent_root(monkeypatch, tmp_path):
    root = tmp_path / "persistent"
    monkeypatch.setenv("UPLOAD_DIR", str(root))

    resolved = resolve_stored_path("uploads/originals/example.wav")

    assert resolved == root / "originals" / "example.wav"


def test_absolute_stored_path_is_preserved(monkeypatch, tmp_path):
    root = tmp_path / "persistent"
    monkeypatch.setenv("UPLOAD_DIR", str(root))
    absolute = tmp_path / "elsewhere" / "asset.png"

    assert resolve_stored_path(str(absolute)) == absolute


def test_certificate_verify_reads_from_active_persistent_root(monkeypatch, tmp_path):
    root = tmp_path / "persistent"
    monkeypatch.setenv("UPLOAD_DIR", str(root))
    layout = ensure_upload_layout()
    certificate_file = layout["certificates"] / "OV-STORAGE.json"
    certificate_file.write_text('{"omni_id":"OV-STORAGE","metadata_lock":{"sha256":"abc"}}')

    class NoDatabaseFallback:
        def query(self, *_args, **_kwargs):
            raise AssertionError("database fallback should not run when disk certificate exists")

    payload = certificate_verify._load_certificate_by_omni_id(
        "OV-STORAGE", NoDatabaseFallback()
    )

    assert payload["omni_id"] == "OV-STORAGE"


def test_c2pa_registered_asset_remaps_legacy_source_path(monkeypatch, tmp_path):
    root = tmp_path / "persistent"
    monkeypatch.setenv("UPLOAD_DIR", str(root))
    original = ensure_upload_layout()["originals"] / "legacy.png"
    original.write_bytes(b"image")

    asset = SimpleNamespace(
        original_path="uploads/originals/legacy.png",
        omni_id="OV-C2PA",
        sha256="abc",
        filename="legacy.png",
    )
    tenant = SimpleNamespace(tenant_id="tenant-a")

    monkeypatch.setattr(c2pa, "get_asset", lambda _db, _omni_id, _tenant_id: asset)
    monkeypatch.setattr(c2pa, "read_c2pa_path", lambda path: {"source_path": path})

    result = c2pa.read_registered_asset_c2pa("OV-C2PA", tenant=tenant, db=object())

    assert result["c2pa"]["source_path"] == str(original)


def test_spectra_registered_asset_remaps_legacy_source_path(monkeypatch, tmp_path):
    root = tmp_path / "persistent"
    monkeypatch.setenv("UPLOAD_DIR", str(root))
    original = ensure_upload_layout()["originals"] / "legacy.wav"
    original.write_bytes(b"audio")

    asset = SimpleNamespace(
        original_path="uploads/originals/legacy.wav",
        omni_id="OV-SPECTRA",
        filename="legacy.wav",
        sha256="abc",
        ai_detection_score=None,
        watermark_applied=False,
        watermark_visible=False,
        watermark_invisible=False,
        asset_type="audio",
        trust_score=0.8,
        content_label="human",
    )
    tenant = SimpleNamespace(tenant_id="tenant-a")

    monkeypatch.setattr(spectra, "get_asset", lambda _db, _omni_id, _tenant_id: asset)
    monkeypatch.setattr(spectra, "get_metadata_by_omni_id", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(spectra, "get_public_humanproof_summary", lambda *_args: None)
    monkeypatch.setattr(spectra, "read_c2pa_path", lambda path: {"source_path": path})
    monkeypatch.setattr(spectra, "build_omnispectra_report", lambda **kwargs: kwargs)

    result = spectra.get_registered_spectra_report(
        "OV-SPECTRA", tenant=tenant, db=object()
    )

    assert result["c2pa"]["source_path"] == str(original)


def test_export_fallback_files_remap_to_persistent_root(monkeypatch, tmp_path):
    root = tmp_path / "persistent"
    monkeypatch.setenv("UPLOAD_DIR", str(root))
    layout = ensure_upload_layout()

    certificate_file = layout["certificates"] / "OV-EXPORT.json"
    certificate_file.write_text('{"omni_id":"OV-EXPORT"}')
    manifest_file = layout["manifests"] / "OV-EXPORT.json"
    manifest_file.write_text('{"manifest_version":"1.1","omni_id":"OV-EXPORT"}')

    asset = SimpleNamespace(
        omni_id="OV-EXPORT",
        certificates=[],
        certificate_path="uploads/certificates/OV-EXPORT.json",
        manifest_path="uploads/manifests/OV-EXPORT.json",
    )

    certificate = export_package._get_certificate(asset)
    manifest = export_package._get_manifest(asset)

    assert '"omni_id":"OV-EXPORT"' in certificate
    assert '"omni_id": "OV-EXPORT"' in manifest
