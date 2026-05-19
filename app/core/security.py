from app.core.config import settings
from fastapi import HTTPException, Security
from fastapi.security.api_key import APIKeyHeader
import secrets

API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)

async def verify_api_key(api_key: str = Security(API_KEY_HEADER)) -> str:
    if not api_key:
        raise HTTPException(status_code=401, detail="X-API-Key header required")
    if not secrets.compare_digest(api_key, settings.omni_api_key):
        raise HTTPException(status_code=403, detail="Invalid API key")
    return api_key
