from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from datetime import datetime

from app.core.tenant import require_admin, generate_api_key
from app.db.session import get_db
from app.db.models import Client
from app.db.seed import seed_demo_client

router = APIRouter(prefix="/admin", tags=["admin"])


# ── GET /admin/clients ────────────────────────────────────────────────────────

@router.get("/clients", dependencies=[Depends(require_admin)])
def list_clients(
    status: str | None = None,
    limit: int = 100,
    db: Session = Depends(get_db),
):
    q = db.query(Client)
    if status:
        q = q.filter(Client.status == status)
    clients = q.order_by(Client.created_at.desc()).limit(limit).all()
    return {
        "total": len(clients),
        "items": [_client_summary(c) for c in clients],
    }


# ── GET /admin/clients/{id} ───────────────────────────────────────────────────

@router.get("/clients/{client_id}", dependencies=[Depends(require_admin)])
def get_client(client_id: str, db: Session = Depends(get_db)):
    client = _get_or_404(db, client_id)
    return _client_detail(client)


# ── POST /admin/clients/{id}/approve ─────────────────────────────────────────

@router.post("/clients/{client_id}/approve", dependencies=[Depends(require_admin)])
def approve_client(client_id: str, db: Session = Depends(get_db)):
    client = _get_or_404(db, client_id)

    if client.status == "approved":
        raise HTTPException(400, detail="Client is already approved")

    raw_key, key_hash = generate_api_key()
    client.status = "approved"
    client.api_key_hash = key_hash
    client.approved_at = datetime.utcnow()
    db.commit()

    return {
        "message": f"{client.company_name} approved",
        "tenant_id": client.tenant_id,
        "api_key": raw_key,           # shown ONCE — not stored
        "warning": "Save this API key — it will not be shown again.",
    }


# ── POST /admin/clients/{id}/suspend ─────────────────────────────────────────

@router.post("/clients/{client_id}/suspend", dependencies=[Depends(require_admin)])
def suspend_client(client_id: str, db: Session = Depends(get_db)):
    client = _get_or_404(db, client_id)

    if client.status == "suspended":
        raise HTTPException(400, detail="Client is already suspended")
    if client.tenant_id == "demo-tenant":
        raise HTTPException(400, detail="Cannot suspend the demo tenant")

    client.status = "suspended"
    db.commit()

    return {"message": f"{client.company_name} suspended", "tenant_id": client.tenant_id}


# ── POST /admin/clients/{id}/regenerate-key ───────────────────────────────────

@router.post("/clients/{client_id}/regenerate-key", dependencies=[Depends(require_admin)])
def regenerate_key(client_id: str, db: Session = Depends(get_db)):
    client = _get_or_404(db, client_id)

    raw_key, key_hash = generate_api_key()
    client.api_key_hash = key_hash
    db.commit()

    return {
        "message": f"API key regenerated for {client.company_name}",
        "tenant_id": client.tenant_id,
        "api_key": raw_key,           # shown ONCE — not stored
        "warning": "Save this API key — it will not be shown again.",
    }


# ── POST /admin/seed-demo-client ──────────────────────────────────────────────

@router.post("/seed-demo-client", dependencies=[Depends(require_admin)])
def seed_demo_client_endpoint(db: Session = Depends(get_db)):
    seed_demo_client(db)
    demo = db.query(Client).filter(Client.tenant_id == "demo-tenant").first()
    return {
        "message": "Demo client seeded",
        "client": _client_summary(demo) if demo else None,
    }


# ── Internal helpers ──────────────────────────────────────────────────────────

def _get_or_404(db: Session, client_id: str) -> Client:
    client = db.query(Client).filter(Client.id == client_id).first()
    if not client:
        raise HTTPException(404, detail="Client not found")
    return client


def _client_summary(c: Client) -> dict:
    return {
        "id": c.id,
        "tenant_id": c.tenant_id,
        "company_name": c.company_name,
        "contact_name": c.contact_name,
        "email": c.email,
        "industry": c.industry,
        "status": c.status,
        "plan": c.plan,
        "created_at": c.created_at.isoformat() if c.created_at else None,
        "approved_at": c.approved_at.isoformat() if c.approved_at else None,
    }


def _client_detail(c: Client) -> dict:
    return {
        **_client_summary(c),
        "phone": c.phone,
        "intended_use": c.intended_use,
        "website": c.website,
        "has_api_key": c.api_key_hash is not None,
    }
