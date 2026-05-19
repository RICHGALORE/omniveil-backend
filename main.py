from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from contextlib import asynccontextmanager
from dotenv import load_dotenv
import os

load_dotenv()

limiter = Limiter(key_func=get_remote_address)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Create all DB tables
    from app.db.session import init_db, SessionLocal
    init_db()

    # Ensure storage folders exist
    for folder in ("uploads/originals", "uploads/watermarked",
                   "uploads/certificates", "uploads/manifests"):
        os.makedirs(folder, exist_ok=True)

    # Seed the demo tenant on first run
    _seed_demo_tenant(SessionLocal())

    yield


def _seed_demo_tenant(db) -> None:
    """
    Create the default demo tenant if it doesn't exist.
    Uses OMNI_API_KEY from env (or the config default) as its API key.
    This tenant owns all uploads made without a registered client.
    """
    from app.db.models import Client
    from app.core.tenant import hash_api_key
    from app.core.config import settings
    from datetime import datetime
    import uuid

    if db.query(Client).filter(Client.tenant_id == "demo-tenant").first():
        db.close()
        return

    raw_key = settings.omni_api_key
    client = Client(
        id=str(uuid.uuid4()),
        tenant_id="demo-tenant",
        company_name="Omni Veil Demo",
        contact_name="Demo User",
        email="demo@omniveil.internal",
        industry="Technology",
        status="approved",
        plan="founder",
        api_key_hash=hash_api_key(raw_key),
        created_at=datetime.utcnow(),
        approved_at=datetime.utcnow(),
    )
    db.add(client)
    db.commit()
    db.close()
    print(f"[startup] Demo tenant seeded — API key: {raw_key}")


app = FastAPI(
    title="Omni Veil Trust OS",
    description="Content provenance, watermarking, and verification API",
    version="0.1.0",
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(GZipMiddleware, minimum_size=1000)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:3001",
        "http://localhost:3002",
        "http://localhost:3003",
        "http://localhost:3004",
        "http://localhost:3005",
        "http://localhost:3006",
        "http://localhost:3007",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from app.api.v1.router import api_router
app.include_router(api_router, prefix="/api/v1")

@app.get("/health")
async def health():
    return {"status": "ok", "version": "0.1.0", "env": os.getenv("APP_ENV", "development")}

@app.get("/")
async def root():
    return {"message": "Omni Veil Trust OS", "docs": "/docs"}
