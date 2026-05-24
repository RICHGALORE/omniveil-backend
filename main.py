from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from contextlib import asynccontextmanager
from dotenv import load_dotenv
import os
import sys

load_dotenv()

limiter = Limiter(key_func=get_remote_address)


@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        init_db()

        db = SessionLocal()
        try:
            seed_demo_client(db)
        finally:
            db.close()

        print("Omni Veil startup database init/seed complete.")
    except Exception as exc:
        # Do not crash the whole Render service on database startup failure.
        # Health endpoint must stay available so infrastructure can be debugged safely.
        print(f"WARNING: Omni Veil database startup init/seed failed: {exc}", file=sys.stderr)

    yield

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
from app.db.session import init_db, SessionLocal
from app.db.seed import seed_demo_client
app.include_router(api_router, prefix="/api/v1")

@app.get("/health")
async def health():
    return {"status": "ok", "version": "0.1.0", "env": os.getenv("ENVIRONMENT", os.getenv("APP_ENV", "development"))}

@app.get("/")
async def root():
    return {"message": "Omni Veil Trust OS", "docs": "/docs"}
