from fastapi.testclient import TestClient

import main
from app.services import readiness


def test_ready_route_returns_200_when_dependencies_are_ready(monkeypatch):
    monkeypatch.setattr(
        main,
        "readiness_snapshot",
        lambda: {
            "status": "ready",
            "ready": True,
            "environment": "test",
            "checks": {"database": True, "storage": True, "trust_signing": True},
        },
    )

    with TestClient(main.app, raise_server_exceptions=False) as client:
        response = client.get("/ready")

    assert response.status_code == 200
    assert response.json()["ready"] is True


def test_ready_route_returns_503_when_a_required_dependency_fails(monkeypatch):
    monkeypatch.setattr(
        main,
        "readiness_snapshot",
        lambda: {
            "status": "not_ready",
            "ready": False,
            "environment": "production",
            "checks": {"database": True, "storage": True, "trust_signing": False},
        },
    )

    with TestClient(main.app, raise_server_exceptions=False) as client:
        response = client.get("/ready")

    assert response.status_code == 503
    assert response.json() == {
        "status": "not_ready",
        "ready": False,
        "environment": "production",
        "checks": {"database": True, "storage": True, "trust_signing": False},
    }


def test_development_readiness_checks_database_and_writable_storage(monkeypatch, tmp_path):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("UPLOAD_DIR", str(tmp_path / "uploads"))
    main.init_db()

    snapshot = readiness.readiness_snapshot()

    assert snapshot["ready"] is True
    assert snapshot["checks"] == {
        "database": True,
        "storage": True,
        "trust_signing": True,
    }


def test_production_missing_signing_material_fails_closed_without_secret_details(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "production")
    for name in (
        "OV_SIGNING_PRIVATE_KEY_B64",
        "OV_SIGNING_PUBLIC_KEY_B64",
        "OV_SIGNING_KEY_ID",
    ):
        monkeypatch.delenv(name, raising=False)

    monkeypatch.setattr(readiness, "_database_ready", lambda: True)
    monkeypatch.setattr(readiness, "_storage_ready", lambda: True)

    snapshot = readiness.readiness_snapshot()

    assert snapshot == {
        "status": "not_ready",
        "ready": False,
        "environment": "production",
        "checks": {"database": True, "storage": True, "trust_signing": False},
    }
    assert "OV_SIGNING" not in str(snapshot)
