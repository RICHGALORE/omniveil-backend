from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from contextlib import asynccontextmanager
from dotenv import load_dotenv
import os
import sys

load_dotenv()

from app.core.rate_limits import explicit_rate_limit_response, limiter


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


@app.middleware("http")
async def enforce_expensive_route_limits(request, call_next):
    limited = explicit_rate_limit_response(request)
    if limited is not None:
        return limited
    return await call_next(request)


app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(GZipMiddleware, minimum_size=1000)

local_origins = [
    "http://localhost:3000",
    "http://localhost:3001",
    "http://localhost:3002",
    "http://localhost:3003",
    "http://localhost:3004",
    "http://localhost:3005",
    "http://localhost:3006",
    "http://localhost:3007",
]
configured_origins = [
    origin.strip().rstrip("/")
    for origin in os.getenv("ALLOWED_ORIGINS", os.getenv("FRONTEND_URL", "")).split(",")
    if origin.strip()
]
allowed_origins = list(dict.fromkeys([*local_origins, *configured_origins]))

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from app.api.v1.router import api_router
from app.db.session import init_db, SessionLocal
from app.db.seed import seed_demo_client
from app.services.readiness import readiness_snapshot
app.include_router(api_router, prefix="/api/v1")

@app.get("/health")
async def health():
    return {"status": "ok", "version": "0.1.0", "env": os.getenv("ENVIRONMENT", os.getenv("APP_ENV", "development"))}

@app.get("/ready")
async def ready():
    snapshot = readiness_snapshot()
    if snapshot["ready"]:
        return snapshot
    return JSONResponse(status_code=503, content=snapshot)

@app.get("/")
async def root():
    return {"message": "Omni Veil Trust OS", "docs": "/docs"}
