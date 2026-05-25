"""
Tenant resolution and admin authentication dependencies.
"""

import hashlib
import os
import secrets

from fastapi import Depends, HTTPException, Security
from fastapi.security import APIKeyHeader
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.db.models import Client

# ── API key headers ───────────────────────────────────────────────────────────

_CLIENT_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)
_ADMIN_KEY_HEADER = APIKeyHeader(name="X-Admin-Key", auto_error=False)

ADMIN_API_KEY = os.getenv("ADMIN_API_KEY")


# ── Helpers ───────────────────────────────────────────────────────────────────

def hash_api_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode()).hexdigest()


def generate_api_key() -> tuple[str, str]:
    """Return (raw_key, key_hash). Raw key is shown once — never stored."""
    raw = f"ov_live_{secrets.token_hex(24)}"
    return raw, hash_api_key(raw)


# ── Client / tenant dependency ────────────────────────────────────────────────

def resolve_tenant(
    api_key: str = Security(_CLIENT_KEY_HEADER),
    db: Session = Depends(get_db),
) -> Client:
    """
    Dependency for all protected endpoints.
    Validates X-API-Key header against the clients table and returns the
    active Client record.  Raises 401/403 on failure.
    """
    if not api_key:
        raise HTTPException(status_code=401, detail="X-API-Key header required")

    key_hash = hash_api_key(api_key)
    client: Client | None = (
        db.query(Client).filter(Client.api_key_hash == key_hash).first()
    )

    if not client:
        raise HTTPException(status_code=403, detail="Invalid API key")

    if client.status == "pending":
        raise HTTPException(
            status_code=403,
            detail="Account pending approval — check your email for updates",
        )
    if client.status == "suspended":
        raise HTTPException(
            status_code=403,
            detail="Account suspended — contact support@omniveil.com",
        )
    if client.status != "approved":
        raise HTTPException(status_code=403, detail="Account not active")

    return client


# ── Admin dependency ──────────────────────────────────────────────────────────

def require_admin(admin_key: str = Security(_ADMIN_KEY_HEADER)) -> None:
    """
    Dependency for all /admin/* endpoints.
    Validates the X-Admin-Key header against ADMIN_API_KEY env var.
    """
    if not ADMIN_API_KEY or not admin_key or not secrets.compare_digest(admin_key, ADMIN_API_KEY):
        raise HTTPException(status_code=403, detail="Admin access required")
