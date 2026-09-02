"""Deployment readiness checks for Omni Veil Trust OS.

`/health` answers whether the API process is alive. Readiness is stricter: it
checks the dependencies required to safely accept new Trust OS work without
exposing secret values or infrastructure details.
"""
from __future__ import annotations

import os
from pathlib import Path

from sqlalchemy import text

from app.db.session import SessionLocal
from app.services.crypto_signing import get_trust_signing_material


def _environment() -> str:
    return os.getenv("ENVIRONMENT", os.getenv("APP_ENV", "development")).strip().lower()


def _database_ready() -> bool:
    db = SessionLocal()
    try:
        db.execute(text("SELECT 1"))
        return True
    finally:
        db.close()


def _storage_ready() -> bool:
    base = Path(os.getenv("UPLOAD_DIR", "uploads"))
    base.mkdir(parents=True, exist_ok=True)
    probe = base / ".omniveil-readiness"
    try:
        probe.write_bytes(b"ready")
        return probe.read_bytes() == b"ready"
    finally:
        try:
            probe.unlink(missing_ok=True)
        except OSError:
            pass


def _signing_ready(environment: str) -> bool:
    # Development/test deliberately use the persistent local development root.
    # Production must have validated external Ed25519 signing material.
    if environment != "production":
        return True
    get_trust_signing_material(environment="production")
    return True


def readiness_snapshot() -> dict:
    """Return a public-safe readiness snapshot.

    Individual failures are reduced to booleans so this endpoint can be used by
    infrastructure without leaking database URLs, paths, key IDs, or secrets.
    """
    environment = _environment()
    checks: dict[str, bool] = {}

    for name, check in (
        ("database", _database_ready),
        ("storage", _storage_ready),
        ("trust_signing", lambda: _signing_ready(environment)),
    ):
        try:
            checks[name] = bool(check())
        except Exception:
            checks[name] = False

    ready = all(checks.values())
    return {
        "status": "ready" if ready else "not_ready",
        "ready": ready,
        "environment": environment,
        "checks": checks,
    }
