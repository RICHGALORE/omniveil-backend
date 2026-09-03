from pathlib import Path

from app.core.storage import ensure_upload_layout, resolve_stored_path, upload_root


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
