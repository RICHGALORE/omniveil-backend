from app.api.v1.endpoints import certificate_verify
from fastapi import APIRouter

from app.api.v1.endpoints.ingest import router as ingest_router
from app.api.v1.endpoints.verify import router as verify_router
from app.api.v1.endpoints.registry import router as registry_router
from app.api.v1.endpoints.admin import router as admin_router
from app.api.v1.endpoints.clients import router as clients_router
from app.api.v1.endpoints.metadata import router as metadata_router
from app.api.v1.endpoints.humanproof import router as humanproof_router
from app.api.v1.endpoints.human_transformation import router as human_transformation_router
from app.api.v1.endpoints.humanproof_publication import router as humanproof_publication_router
from app.api.v1.endpoints.c2pa import router as c2pa_router
from app.api.v1.endpoints.spectra import router as spectra_router
from app.api.v1.endpoints.evidence import router as evidence_router
from app.api.v1.endpoints.dpp import router as dpp_router
from app.api.v1.endpoints.integrity import router as integrity_router

api_router = APIRouter()

api_router.include_router(ingest_router)
api_router.include_router(verify_router)
api_router.include_router(registry_router)
api_router.include_router(admin_router)
api_router.include_router(clients_router)
api_router.include_router(metadata_router)
api_router.include_router(humanproof_router)
api_router.include_router(human_transformation_router)
api_router.include_router(humanproof_publication_router)
api_router.include_router(c2pa_router)
api_router.include_router(spectra_router)
api_router.include_router(evidence_router)
api_router.include_router(dpp_router)
api_router.include_router(integrity_router)

api_router.include_router(certificate_verify.router, prefix="", tags=["Certificate Verification"])
