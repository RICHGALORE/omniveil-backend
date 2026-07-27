"""
Follow-up defect A — public registry endpoint 500.

`registry.get_public_registry_asset` reads `asset.certificate_class` and
`asset.certificate_class_label`. Those columns exist in the DB (additive
migration) but were not declared on the `Asset` ORM model, so the attribute
access raised AttributeError -> HTTP 500. This test proves that after declaring
the columns, GET /api/v1/registry/assets/{omni_id} returns 200 with the
expected response shape.
"""
import io
import json
import uuid

from fastapi.testclient import TestClient
from PIL import Image

import main
from app.db.session import SessionLocal
from app.db.models import Client
from app.core.tenant import hash_api_key

RAW_KEY = "ov_live_registry_test_key_0001"


def _ensure_client():
    db = SessionLocal()
    try:
        kh = hash_api_key(RAW_KEY)
        if not db.query(Client).filter(Client.api_key_hash == kh).first():
            db.add(Client(
                id=str(uuid.uuid4()),
                tenant_id="registry-test-tenant",
                company_name="Registry Test Co",
                email="registry-test@example.com",
                status="approved",
                plan="creator",
                api_key_hash=kh,
            ))
            db.commit()
    finally:
        db.close()


def _png_bytes():
    img = Image.new("RGB", (32, 32), (10, 120, 220))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def test_public_registry_asset_returns_200():
    # Enter the TestClient context first so the app lifespan runs init_db()
    # and creates the tables before we seed the test client.
    with TestClient(main.app, raise_server_exceptions=False) as client:
        _ensure_client()
        headers = {"X-API-Key": RAW_KEY}
        files = {"file": ("reg.png", _png_bytes(), "image/png")}
        data = {"provenance_json": json.dumps({"creator_name": "Alice Example"}),
                "options_json": "{}"}
        up = client.post("/api/v1/upload", headers=headers, files=files, data=data)
        assert up.status_code == 200, up.text
        omni_id = up.json()["omni_id"]

        r = client.get(f"/api/v1/registry/assets/{omni_id}", headers=headers)
        assert r.status_code == 200, r.text
        body = r.json()
        # Response shape preserved: the previously-crashing keys are present.
        assert "certificate_class" in body
        assert "certificate_class_label" in body
        assert body.get("omni_id") == omni_id
