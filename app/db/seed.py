import hashlib
import os
import secrets
from datetime import datetime

from app.db.models import Client

SEED_DEMO_CLIENT = os.getenv("SEED_DEMO_CLIENT", "true").lower() == "true"
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

    raw_key = os.getenv("DEMO_API_KEY") or secrets.token_urlsafe(32)
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

    print(
        f"Seed: Demo tenant created "
        f"(id={demo.id}, tenant_id={demo.tenant_id}). "
        "Save the API key shown below; it will not be shown again."
    )
    print(f"Seed: Demo API key = {raw_key}")

    return demo
