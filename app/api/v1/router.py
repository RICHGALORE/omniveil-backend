from fastapi import APIRouter

from app.api.v1.endpoints.ingest import router as ingest_router
from app.api.v1.endpoints.verify import router as verify_router
from app.api.v1.endpoints.registry import router as registry_router
from app.api.v1.endpoints.admin import router as admin_router
from app.api.v1.endpoints.clients import router as clients_router

api_router = APIRouter()

api_router.include_router(ingest_router)
api_router.include_router(verify_router)
api_router.include_router(registry_router)
api_router.include_router(admin_router)
api_router.include_router(clients_router)
