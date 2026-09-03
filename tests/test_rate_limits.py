from starlette.requests import Request

from app.core.rate_limits import explicit_rate_limit_response, tenant_or_ip_key


def _request(path: str, api_key: str, method: str = "POST") -> Request:
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method,
        "scheme": "https",
        "path": path,
        "raw_path": path.encode("utf-8"),
        "query_string": b"",
        "headers": [(b"x-api-key", api_key.encode("utf-8"))],
        "client": ("127.0.0.1", 50000),
        "server": ("testserver", 443),
    }
    return Request(scope)


def test_rate_limit_key_hashes_api_secret():
    request = _request("/api/v1/upload", "super-secret-tenant-key")
    key = tenant_or_ip_key(request)

    assert key.startswith("tenant-key:")
    assert "super-secret-tenant-key" not in key


def test_expensive_upload_route_is_limited_per_tenant(monkeypatch):
    monkeypatch.setenv("OV_RATE_LIMIT_UPLOAD", "2/minute")
    tenant_a = "rate-test-tenant-a"

    assert explicit_rate_limit_response(_request("/api/v1/upload", tenant_a)) is None
    assert explicit_rate_limit_response(_request("/api/v1/upload", tenant_a)) is None

    blocked = explicit_rate_limit_response(_request("/api/v1/upload", tenant_a))
    assert blocked is not None
    assert blocked.status_code == 429
    assert blocked.headers["retry-after"] == "60"

    # A separate tenant receives an independent bucket.
    assert explicit_rate_limit_response(
        _request("/api/v1/upload", "rate-test-tenant-b")
    ) is None


def test_public_verify_is_not_part_of_expensive_route_limits(monkeypatch):
    monkeypatch.setenv("OV_RATE_LIMIT_UPLOAD", "1/minute")
    request = _request("/api/v1/verify/OV-TEST", "rate-test-public", method="GET")

    assert explicit_rate_limit_response(request) is None


def test_bad_environment_override_falls_back_to_safe_default(monkeypatch):
    monkeypatch.setenv("OV_RATE_LIMIT_C2PA_READ", "not-a-limit")
    request = _request("/api/v1/c2pa/read", "rate-test-bad-config")

    assert explicit_rate_limit_response(request) is None
