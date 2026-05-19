from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session
from datetime import datetime
import hashlib, uuid

from app.core.tenant import resolve_tenant
from app.db.session import get_db
from app.db.models import Client

router = APIRouter(prefix="/clients", tags=["clients"])


# ── Request schemas ───────────────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    company_name: str
    contact_name: str
    email: EmailStr
    phone: str | None = None
    industry: str | None = None
    intended_use: str | None = None
    website: str | None = None
    plan: str = "creator"           # founder | creator | label | enterprise


# ── POST /clients/register ────────────────────────────────────────────────────

@router.post("/register", status_code=201)
def register_client(payload: RegisterRequest, db: Session = Depends(get_db)):
    """
    Public endpoint — submit a client onboarding application.
    Creates a pending record; an API key is only issued after admin approval.
    """
    existing = db.query(Client).filter(Client.email == payload.email).first()
    if existing:
        raise HTTPException(409, detail="An account with this email already exists")

    valid_plans = {"founder", "creator", "label", "enterprise"}
    if payload.plan not in valid_plans:
        raise HTTPException(400, detail=f"plan must be one of {sorted(valid_plans)}")

    tenant_id = _make_tenant_id(payload.email)
    # Guarantee uniqueness if hash collision
    if db.query(Client).filter(Client.tenant_id == tenant_id).first():
        tenant_id = f"{tenant_id}_{uuid.uuid4().hex[:4]}"

    client = Client(
        id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        company_name=payload.company_name,
        contact_name=payload.contact_name,
        email=payload.email,
        phone=payload.phone,
        industry=payload.industry,
        intended_use=payload.intended_use,
        website=payload.website,
        status="pending",
        plan=payload.plan,
        api_key_hash=None,
        created_at=datetime.utcnow(),
    )
    db.add(client)
    db.commit()

    return {
        "message": "Application received — you will be notified by email upon approval",
        "tenant_id": client.tenant_id,
        "status": "pending",
    }


# ── GET /clients/me ───────────────────────────────────────────────────────────

@router.get("/me")
def get_my_account(tenant: Client = Depends(resolve_tenant)):
    """Return the authenticated client's own account details."""
    return {
        "id": tenant.id,
        "tenant_id": tenant.tenant_id,
        "company_name": tenant.company_name,
        "contact_name": tenant.contact_name,
        "email": tenant.email,
        "industry": tenant.industry,
        "website": tenant.website,
        "status": tenant.status,
        "plan": tenant.plan,
        "created_at": tenant.created_at.isoformat() if tenant.created_at else None,
        "approved_at": tenant.approved_at.isoformat() if tenant.approved_at else None,
    }


# ── Internal ──────────────────────────────────────────────────────────────────

def _make_tenant_id(email: str) -> str:
    slug = hashlib.md5(email.lower().encode()).hexdigest()[:8].upper()
    return f"tn_{slug}"
