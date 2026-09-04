from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.tenant import resolve_tenant
from app.db import get_asset
from app.db.dpp_models import DigitalProductPassport
from app.db.models import Client
from app.db.session import get_db
from app.services.dpp import (
    ESPR_FRAMEWORK,
    GS1_RESOLVER_STANDARD_VERSION,
    GS1_URI_SYNTAX_VERSION,
    build_gs1_item_uri,
    normalize_resolver_base,
    public_dpp_record,
    validate_gtin14,
    validate_serial,
)


router = APIRouter(prefix="/dpp", tags=["Digital Product Passport"])


class DPPUpsertRequest(BaseModel):
    product_name: str | None = Field(default=None, max_length=240)
    brand_name: str | None = Field(default=None, max_length=240)
    gtin14: str | None = Field(default=None, max_length=14)
    serial_number: str | None = Field(default=None, max_length=20)
    data_carrier_type: Literal["qr", "data_matrix", "nfc", "other"] | None = None
    resolver_base_url: str | None = Field(default=None, max_length=500)


def _clean_optional(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = value.strip()
    return cleaned or None


@router.post("/assets/{omni_id}")
def upsert_asset_dpp(
    omni_id: str,
    payload: DPPUpsertRequest,
    tenant: Client = Depends(resolve_tenant),
    db: Session = Depends(get_db),
):
    """Create or update a generic item-level DPP readiness record.

    This endpoint validates identifier syntax and binds the passport record to a
    tenant-owned Omni asset. It does not certify GS1 licensing/entitlement or EU
    regulatory compliance.
    """
    asset = get_asset(db, omni_id, tenant.tenant_id)
    if not asset:
        raise HTTPException(404, "Asset not found")

    gtin_input = _clean_optional(payload.gtin14)
    serial_input = _clean_optional(payload.serial_number)
    if bool(gtin_input) != bool(serial_input):
        raise HTTPException(
            422,
            "GTIN-14 and serial number must be supplied together for an item-level GS1 Digital Link.",
        )

    try:
        gtin14 = validate_gtin14(gtin_input) if gtin_input else None
        serial_number = validate_serial(serial_input) if serial_input else None
        resolver_base = normalize_resolver_base(payload.resolver_base_url)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc

    canonical_uri = None
    resolver_uri = None
    if gtin14 and serial_number:
        canonical_uri = build_gs1_item_uri(
            "https://id.gs1.org",
            gtin14,
            serial_number,
        )
        if resolver_base:
            resolver_uri = build_gs1_item_uri(
                resolver_base,
                gtin14,
                serial_number,
            )
    elif resolver_base:
        raise HTTPException(
            422,
            "A resolver base URL requires GTIN-14 and serial number identifiers.",
        )

    record = (
        db.query(DigitalProductPassport)
        .filter(
            DigitalProductPassport.omni_id == omni_id,
            DigitalProductPassport.tenant_id == tenant.tenant_id,
        )
        .first()
    )

    now = datetime.utcnow()
    if record is None:
        record = DigitalProductPassport(
            passport_id=f"OV-DPP-{uuid.uuid4().hex.upper()}",
            omni_id=omni_id,
            tenant_id=tenant.tenant_id,
            passport_level="item",
            created_at=now,
        )
        db.add(record)

    record.product_name = _clean_optional(payload.product_name)
    record.brand_name = _clean_optional(payload.brand_name)
    record.gtin14 = gtin14
    record.serial_number = serial_number
    record.data_carrier_type = payload.data_carrier_type
    record.canonical_gs1_uri = canonical_uri
    record.resolver_uri = resolver_uri
    record.gs1_uri_syntax_version = GS1_URI_SYNTAX_VERSION
    record.gs1_resolver_standard_version = GS1_RESOLVER_STANDARD_VERSION
    record.regulatory_framework = ESPR_FRAMEWORK
    record.regulatory_status = "readiness_only"
    record.updated_at = now

    db.commit()
    db.refresh(record)
    return public_dpp_record(record)


@router.get("/assets/{omni_id}")
def get_asset_dpp(
    omni_id: str,
    tenant: Client = Depends(resolve_tenant),
    db: Session = Depends(get_db),
):
    """Return the tenant-scoped DPP readiness record for an asset."""
    asset = get_asset(db, omni_id, tenant.tenant_id)
    if not asset:
        raise HTTPException(404, "Asset not found")

    record = (
        db.query(DigitalProductPassport)
        .filter(
            DigitalProductPassport.omni_id == omni_id,
            DigitalProductPassport.tenant_id == tenant.tenant_id,
        )
        .first()
    )
    if record is None:
        raise HTTPException(404, "Digital Product Passport record not found")

    return public_dpp_record(record)
