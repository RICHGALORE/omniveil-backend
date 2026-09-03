import hashlib
import os

from fastapi import Request
from slowapi import Limiter
from slowapi.util import get_remote_address


def tenant_or_ip_key(request: Request) -> str:
    """Rate-limit authenticated API traffic without storing the raw API key.

    Browser traffic reaches the backend through Vercel, so remote-IP-only limits
    can unintentionally group unrelated users together. Prefer a stable digest of
    the tenant API key when present and fall back to the remote address for any
    unauthenticated/internal request.
    """
    api_key = (request.headers.get("x-api-key") or "").strip()
    if api_key:
        digest = hashlib.sha256(api_key.encode("utf-8")).hexdigest()[:24]
        return f"tenant-key:{digest}"
    return f"ip:{get_remote_address(request)}"


def _limit_from_env(name: str, default: str) -> str:
    value = os.getenv(name, default).strip()
    return value or default


def upload_limit() -> str:
    return _limit_from_env("OV_RATE_LIMIT_UPLOAD", "20/minute")


def spectra_scan_limit() -> str:
    return _limit_from_env("OV_RATE_LIMIT_SPECTRA_SCAN", "30/minute")


def c2pa_read_limit() -> str:
    return _limit_from_env("OV_RATE_LIMIT_C2PA_READ", "30/minute")


limiter = Limiter(key_func=tenant_or_ip_key)
