import uuid

from fastapi.testclient import TestClient

import main
from app.core.tenant import hash_api_key
from app.db.models import Asset, Client
from app.db.session import SessionLocal


def _ensure_client(raw_key: str, tenant_id: str) -> None:
    main.init_db()
    db = SessionLocal()
    try:
        db.add(
            Client(
                id=str(uuid.uuid4()),
                tenant_id=tenant_id,
                company_name="DPP Test Brand",
                email=f"dpp-{uuid.uuid4().hex}@example.com",
                status="approved",
                plan="enterprise",
                api_key_hash=hash_api_key(raw_key),
            )
        )
        db.commit()
    finally:
        db.close()


def _create_asset(tenant_id: str) -> str:
    token = uuid.uuid4().hex
    omni_id = f"OV-DPPTEST-{token[:16].upper()}"
    db = SessionLocal()
    try:
        db.add(
            Asset(
                omni_id=omni_id,
                asset_id=f"asset-{token}",
                tenant_id=tenant_id,
                filename="luxury-item-photo.jpg",
                file_type="image/jpeg",
                original_path=f"/tmp/{token}.jpg",
                sha256="a" * 64,
                blake3="b" * 64,
                trust_score=0.75,
                content_label="human",
                creator_name="Test Brand",
            )
        )
        db.commit()
        return omni_id
    finally:
        db.close()


def test_dpp_readiness_builds_gs1_item_uri_and_is_tenant_scoped():
    owner_key = f"ov_dpp_owner_{uuid.uuid4().hex}"
    other_key = f"ov_dpp_other_{uuid.uuid4().hex}"
    owner_tenant = f"dpp-owner-{uuid.uuid4().hex}"
    other_tenant = f"dpp-other-{uuid.uuid4().hex}"
    _ensure_client(owner_key, owner_tenant)
    _ensure_client(other_key, other_tenant)
    omni_id = _create_asset(owner_tenant)

    with TestClient(main.app, raise_server_exceptions=False) as client:
        response = client.post(
            f"/api/v1/dpp/assets/{omni_id}",
            headers={"X-API-Key": owner_key},
            json={
                "product_name": "Test Luxury Item",
                "brand_name": "Test Brand",
                "gtin14": "09506000151519",
                "serial_number": "12345678p901",
                "data_carrier_type": "qr",
                "resolver_base_url": "https://id.example-brand.com",
            },
        )
        assert response.status_code == 200, response.text
        dpp = response.json()

        assert dpp["omni_id"] == omni_id
        assert dpp["passport_level"] == "item"
        assert dpp["product_identifier"]["canonical_gs1_digital_link_uri"] == (
            "https://id.gs1.org/01/09506000151519/21/12345678p901"
        )
        assert dpp["product_identifier"]["resolver_uri"] == (
            "https://id.example-brand.com/01/09506000151519/21/12345678p901"
        )
        assert dpp["product_identifier"]["gs1_identifier_entitlement_verified"] is False
        assert dpp["data_carrier"]["declared_type"] == "qr"
        assert dpp["data_carrier"]["physical_presence_verified"] is False
        assert dpp["standards_profile"]["gs1_digital_link_uri_syntax"] == "1.7.0"
        assert dpp["standards_profile"]["gs1_conformant_resolver"] == "1.2.1"
        assert dpp["standards_profile"]["eu_framework"] == "Regulation (EU) 2024/1781"
        assert dpp["regulatory_status"] == "readiness_only"
        assert dpp["readiness"]["compliance_status"] == "readiness_only"
        assert dpp["readiness"]["checks"]["product_specific_delegated_act_profile_applied"] is False
        assert any("does not certify" in dpp["readiness"]["statement"] for _ in [0])

        loaded = client.get(
            f"/api/v1/dpp/assets/{omni_id}",
            headers={"X-API-Key": owner_key},
        )
        assert loaded.status_code == 200
        assert loaded.json()["passport_id"] == dpp["passport_id"]

        denied = client.get(
            f"/api/v1/dpp/assets/{omni_id}",
            headers={"X-API-Key": other_key},
        )
        assert denied.status_code == 404


def test_dpp_rejects_invalid_gtin_and_partial_instance_identifier():
    owner_key = f"ov_dpp_validation_{uuid.uuid4().hex}"
    tenant_id = f"dpp-validation-{uuid.uuid4().hex}"
    _ensure_client(owner_key, tenant_id)
    omni_id = _create_asset(tenant_id)

    with TestClient(main.app, raise_server_exceptions=False) as client:
        invalid_check_digit = client.post(
            f"/api/v1/dpp/assets/{omni_id}",
            headers={"X-API-Key": owner_key},
            json={
                "gtin14": "09506000151518",
                "serial_number": "SERIAL-1",
                "data_carrier_type": "qr",
            },
        )
        assert invalid_check_digit.status_code == 422
        assert "check digit" in invalid_check_digit.text.lower()

        partial_identifier = client.post(
            f"/api/v1/dpp/assets/{omni_id}",
            headers={"X-API-Key": owner_key},
            json={"gtin14": "09506000151519"},
        )
        assert partial_identifier.status_code == 422
        assert "supplied together" in partial_identifier.text.lower()

        unsafe_resolver = client.post(
            f"/api/v1/dpp/assets/{omni_id}",
            headers={"X-API-Key": owner_key},
            json={
                "gtin14": "09506000151519",
                "serial_number": "SERIAL-1",
                "resolver_base_url": "http://resolver.example.com",
            },
        )
        assert unsafe_resolver.status_code == 422
        assert "https" in unsafe_resolver.text.lower()
