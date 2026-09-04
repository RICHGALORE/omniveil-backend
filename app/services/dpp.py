from __future__ import annotations

import re
from urllib.parse import quote, urlparse

from app.db.dpp_models import DigitalProductPassport


GS1_URI_SYNTAX_VERSION = "1.7.0"
GS1_RESOLVER_STANDARD_VERSION = "1.2.1"
ESPR_FRAMEWORK = "Regulation (EU) 2024/1781"
DPP_PROFILE = "omni-luxury-item-readiness-v0"


def validate_gtin14(value: str) -> str:
    gtin = value.strip()
    if not re.fullmatch(r"\d{14}", gtin):
        raise ValueError("GTIN must contain exactly 14 digits.")

    body = [int(char) for char in gtin[:-1]]
    weighted_total = sum(
        digit * (3 if index % 2 == 0 else 1)
        for index, digit in enumerate(reversed(body))
    )
    expected_check_digit = (10 - (weighted_total % 10)) % 10
    if int(gtin[-1]) != expected_check_digit:
        raise ValueError("GTIN check digit is invalid.")
    return gtin


def validate_serial(value: str) -> str:
    serial = value.strip()
    if not serial:
        raise ValueError("Serial number cannot be empty.")
    if len(serial) > 20:
        raise ValueError("GS1 serial number must be 20 characters or fewer.")
    if any(ord(char) < 32 or ord(char) == 127 for char in serial):
        raise ValueError("Serial number contains unsupported control characters.")
    return serial


def normalize_resolver_base(value: str | None) -> str | None:
    if value is None or not value.strip():
        return None
    candidate = value.strip().rstrip("/")
    parsed = urlparse(candidate)
    if parsed.scheme != "https" or not parsed.netloc:
        raise ValueError("Resolver base URL must be an HTTPS origin.")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("Resolver base URL cannot contain credentials, query, or fragment.")
    if parsed.path not in {"", "/"}:
        raise ValueError("Resolver base URL must not contain a path.")
    return f"https://{parsed.netloc}"


def build_gs1_item_uri(base_url: str, gtin14: str, serial_number: str) -> str:
    encoded_serial = quote(serial_number, safe="-._~")
    return f"{base_url.rstrip('/')}/01/{gtin14}/21/{encoded_serial}"


def dpp_readiness(record: DigitalProductPassport) -> dict:
    has_gs1_instance_id = bool(record.gtin14 and record.serial_number)
    has_carrier = bool(record.data_carrier_type)

    checks = {
        "omni_id_bound": True,
        "passport_level_item": record.passport_level == "item",
        "standardized_instance_identifier_declared": has_gs1_instance_id,
        "gs1_syntax_validated": has_gs1_instance_id,
        "gs1_identifier_license_or_brand_entitlement_verified": False,
        "data_carrier_declared": has_carrier,
        "physical_data_carrier_presence_verified": False,
        "backup_copy_provider_configured": False,
        "product_specific_delegated_act_profile_applied": False,
    }

    gaps: list[str] = []
    if not has_gs1_instance_id:
        gaps.append("A standardized item-level product identifier has not been configured.")
    else:
        gaps.append("Ownership or licensing entitlement for the supplied GS1 identifier has not been verified by Omni Veil.")
    if not has_carrier:
        gaps.append("A product data-carrier type has not been declared.")
    gaps.append("Physical presence and placement of the product data carrier have not been verified.")
    gaps.append("A Digital Product Passport backup-copy service provider is not configured in this V0 profile.")
    gaps.append("Product-specific ESPR delegated-act requirements are not encoded in this generic readiness profile.")

    return {
        "profile": DPP_PROFILE,
        "compliance_status": "readiness_only",
        "checks": checks,
        "gaps": gaps,
        "statement": (
            "This is a Digital Product Passport readiness record. It does not certify "
            "compliance with Regulation (EU) 2024/1781 or any product-specific delegated act."
        ),
    }


def public_dpp_record(record: DigitalProductPassport) -> dict:
    return {
        "passport_id": record.passport_id,
        "omni_id": record.omni_id,
        "passport_level": record.passport_level,
        "product_name": record.product_name,
        "brand_name": record.brand_name,
        "product_identifier": {
            "scheme": "GS1 GTIN + serial" if record.gtin14 and record.serial_number else "Omni ID only",
            "gtin14": record.gtin14,
            "serial_number": record.serial_number,
            "canonical_gs1_digital_link_uri": record.canonical_gs1_uri,
            "resolver_uri": record.resolver_uri,
            "gs1_identifier_entitlement_verified": False,
        },
        "data_carrier": {
            "declared_type": record.data_carrier_type,
            "physical_presence_verified": False,
        },
        "standards_profile": {
            "gs1_digital_link_uri_syntax": record.gs1_uri_syntax_version,
            "gs1_conformant_resolver": record.gs1_resolver_standard_version,
            "eu_framework": record.regulatory_framework,
        },
        "regulatory_status": record.regulatory_status,
        "readiness": dpp_readiness(record),
        "created_at": record.created_at.isoformat() + "Z" if record.created_at else None,
        "updated_at": record.updated_at.isoformat() + "Z" if record.updated_at else None,
        "related_endpoints": {
            "evidence_graph": f"/api/v1/evidence/assets/{record.omni_id}",
            "asset_report": f"/api/v1/assets/{record.omni_id}/report",
            "registry": f"/api/v1/registry/assets/{record.omni_id}",
            "verify": f"/api/v1/verify/{record.omni_id}",
        },
    }
