from app.api.v1.endpoints import certificate_verify
from fastapi import APIRouter

from app.api.v1.endpoints.ingest import router as ingest_router
from app.api.v1.endpoints.verify import router as verify_router
from app.api.v1.endpoints.registry import router as registry_router
from app.api.v1.endpoints.admin import router as admin_router
from app.api.v1.endpoints.clients import router as clients_router
from app.api.v1.endpoints.metadata import router as metadata_router
from app.api.v1.endpoints.humanproof import router as humanproof_router
from app.api.v1.endpoints.c2pa import router as c2pa_router
from app.api.v1.endpoints.spectra import router as spectra_router

api_router = APIRouter()

api_router.include_router(ingest_router)
api_router.include_router(verify_router)
api_router.include_router(registry_router)
api_router.include_router(admin_router)
api_router.include_router(clients_router)
api_router.include_router(metadata_router)
api_router.include_router(humanproof_router)
api_router.include_router(c2pa_router)
api_router.include_router(spectra_router)

api_router.include_router(certificate_verify.router, prefix="", tags=["Certificate Verification"])
