from __future__ import annotations

import os
from pathlib import Path


def upload_root() -> Path:
    """Return the canonical durable upload root for this process.

    Production should set UPLOAD_DIR to the persistent Render disk mount
    (currently /app/uploads). Relative paths remain supported for local dev.
    """
    configured = os.getenv("UPLOAD_DIR", "uploads").strip() or "uploads"
    root = Path(configured).expanduser()
    if not root.is_absolute():
        root = Path.cwd() / root
    return root.resolve()


def ensure_upload_layout() -> dict[str, Path]:
    root = upload_root()
    paths = {
        "root": root,
        "originals": root / "originals",
        "watermarked": root / "watermarked",
        "certificates": root / "certificates",
        "manifests": root / "manifests",
    }
    for path in paths.values():
        path.mkdir(parents=True, exist_ok=True)
    return paths


def resolve_stored_path(value: str | None) -> Path | None:
    """Resolve persisted legacy or canonical asset paths safely.

    Older records store values like ``uploads/originals/foo.png``. When the
    production disk root is configurable, remap those legacy ``uploads/...``
    values beneath the active root while preserving absolute paths.
    """
    if not value:
        return None

    raw = Path(value).expanduser()
    if raw.is_absolute():
        return raw

    local = (Path.cwd() / raw).resolve()
    if local.exists():
        return local

    parts = raw.parts
    if parts and parts[0] == "uploads":
        return upload_root().joinpath(*parts[1:])

    return upload_root() / raw
