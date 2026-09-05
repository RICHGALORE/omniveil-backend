import hashlib
import os
from typing import Callable

from fastapi import Request
from fastapi.responses import JSONResponse
from limits import parse
from slowapi import Limiter
from slowapi.util import get_remote_address


def tenant_or_ip_key(request: Request) -> str:
    """Rate-limit authenticated traffic without storing the raw API key."""
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


def detector_refresh_limit() -> str:
    return _limit_from_env("OV_RATE_LIMIT_DETECTOR_REFRESH", "10/minute")


def c2pa_read_limit() -> str:
    return _limit_from_env("OV_RATE_LIMIT_C2PA_READ", "30/minute")


_STORAGE_URI = os.getenv("OV_RATE_LIMIT_STORAGE_URI", "memory://").strip() or "memory://"
limiter = Limiter(key_func=tenant_or_ip_key, storage_uri=_STORAGE_URI)

# Explicit route rules avoid SlowAPI's current default-limit/router compatibility
# issue on newer FastAPI releases. Public Verify and read-only Trust OS routes are
# deliberately not throttled here.
_ROUTE_LIMITS: dict[tuple[str, str], tuple[Callable[[], str], str]] = {
    ("POST", "/api/v1/upload"): (upload_limit, "20/minute"),
    ("POST", "/api/v1/spectra/scan"): (spectra_scan_limit, "30/minute"),
    ("POST", "/api/v1/c2pa/read"): (c2pa_read_limit, "30/minute"),
}


def _route_limit_rule(request: Request) -> tuple[Callable[[], str], str] | None:
    method = request.method.upper()
    path = request.url.path

    exact = _ROUTE_LIMITS.get((method, path))
    if exact is not None:
        return exact

    # Registered detector refreshes call paid external providers. Match the
    # single Omni-ID path segment explicitly so unrelated Spectra routes do not
    # inherit this bucket by accident.
    prefix = "/api/v1/spectra/assets/"
    suffix = "/detectors"
    if method == "POST" and path.startswith(prefix) and path.endswith(suffix):
        omni_id = path[len(prefix) : -len(suffix)].strip("/")
        if omni_id and "/" not in omni_id:
            return detector_refresh_limit, "10/minute"

    return None


def explicit_rate_limit_response(request: Request) -> JSONResponse | None:
    rule = _route_limit_rule(request)
    if rule is None:
        return None

    limit_provider, safe_default = rule
    try:
        rate = parse(limit_provider())
    except ValueError:
        # A malformed environment override must not disable abuse protection.
        rate = parse(safe_default)

    key = tenant_or_ip_key(request)
    scope = f"{request.method.upper()}:{request.url.path}"
    if limiter.limiter.hit(rate, key, scope):
        return None

    return JSONResponse(
        status_code=429,
        content={"detail": "Too many requests"},
        headers={"Retry-After": "60"},
    )
