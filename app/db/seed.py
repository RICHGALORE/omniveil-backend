import hashlib
import os
import secrets
from datetime import datetime

from app.db.models import Client

ENVIRONMENT = os.getenv("ENVIRONMENT", os.getenv("APP_ENV", "development")).lower()
_seed_setting = os.getenv("SEED_DEMO_CLIENT")
SEED_DEMO_CLIENT = (
    _seed_setting.lower() == "true"
    if _seed_setting is not None
    else ENVIRONMENT != "production"
)
DEMO_TENANT_ID = os.getenv("DEMO_TENANT_ID", "demo-tenant")
DEMO_CLIENT_ID = os.getenv("DEMO_CLIENT_ID", "acb8b49e-0095-421a-a9bb-26ecabe7e62e")


def _hash_api_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode()).hexdigest()


def seed_demo_client(db):
    """
    Idempotent demo tenant seed.

    Safe on every startup:
    - If demo tenant exists, do nothing.
    - If it does not exist, create it once.
    - Never deletes, resets, or recreates existing clients.
    """
    if not SEED_DEMO_CLIENT:
        print("Seed: SEED_DEMO_CLIENT=false — skipping demo tenant seed.")
        return None

    existing = db.query(Client).filter(Client.tenant_id == DEMO_TENANT_ID).first()

    if existing:
        print(
            f"Seed: Demo tenant already exists "
            f"(id={existing.id}, tenant_id={existing.tenant_id}, status={existing.status}). "
            "No changes made."
        )
        return existing

    raw_key = os.getenv("DEMO_API_KEY")
    generated_key = False
    if not raw_key:
        if ENVIRONMENT == "production":
            raise RuntimeError(
                "DEMO_API_KEY is required when demo seeding is enabled in production"
            )
        raw_key = secrets.token_urlsafe(32)
        generated_key = True
    key_hash = _hash_api_key(raw_key)

    demo = Client(
        id=DEMO_CLIENT_ID,
        tenant_id=DEMO_TENANT_ID,
        company_name="Omni Veil Demo",
        contact_name="Demo User",
        email="demo@omniveil.internal",
        industry="Technology",
        status="approved",
        plan="founder",
        api_key_hash=key_hash,
        approved_at=datetime.utcnow(),
    )

    db.add(demo)
    db.commit()
    db.refresh(demo)

    print(f"Seed: Demo tenant created (id={demo.id}, tenant_id={demo.tenant_id}).")
    if generated_key:
        print(
            "Seed: A development-only demo API key was generated. "
            "Set DEMO_API_KEY explicitly when a stable local key is required."
        )

    return demo
