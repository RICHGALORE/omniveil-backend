from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy.orm import Session
import json
import mimetypes

from app.core.tenant import resolve_tenant
from app.db.session import get_db
from app.db.models import Asset, Certificate, Client
from app.db import get_asset, get_all_assets
from app.services.asset_facts import (
    ai_facts,
    asset_identity,
    build_asset_facts,
    human_authorship,
    ownership_facts,
    readiness_facts,
    trust_facts,
)
from app.services.copyright_report import generate_copyright_readiness_report
from app.services.export_package import build_export_package
from app.services.humanproof_public import get_public_humanproof_summary

router = APIRouter()


@router.get("/assets")
def list_assets(
    limit: int = 50,
    tenant: Client = Depends(resolve_tenant),
    db: Session = Depends(get_db),
):
    assets = get_all_assets(db, limit, tenant.tenant_id)
    total_count = (
        db.query(Asset)
        .filter(Asset.tenant_id == tenant.tenant_id)
        .count()
    )
    items = [
        {
            "omni_id": a.omni_id,
            "filename": a.filename,
            "asset_type": a.asset_type,
            "file_type": a.file_type,
            "trust_score": a.trust_score,
            "content_label": a.content_label,
            "creator_name": a.creator_name,
            "ai_disclosure": a.ai_disclosure,
            "certificate_class": a.certificate_class,
            "certificate_class_label": a.certificate_class_label,
            "created_at": a.created_at.isoformat() if a.created_at else None,
            "total_verifications": int(a.total_verifications or 0),
        }
        for a in assets
    ]
    return {
        "items": items,
        "total": total_count,
        "total_count": total_count,
        "returned_count": len(items),
        "limit": limit,
    }


@router.get("/registry/assets/{omni_id}")
def get_public_registry_asset(
    omni_id: str,
    db: Session = Depends(get_db),
):
    """Public-safe registry lookup backed by persisted asset facts."""
    asset = get_asset(db, omni_id)
    if not asset:
        raise HTTPException(404, "Asset not found")

    identity = asset_identity(asset)
    trust = trust_facts(asset)
    ai = ai_facts(asset)
    readiness = readiness_facts(asset)
    rights = ownership_facts(asset, asset.contributors)

    return {
        "omni_id": identity["omni_id"],
        "asset_id": identity["asset_id"],
        "filename": identity["filename"],
        "sha256": identity["sha256"],
        "blake3": identity["blake3"],
        "phash": identity["phash"],
        "trust_score": trust["trust_score"],
        "content_label": trust["content_label"],
        "label_reasons": trust["label_reasons"],
        "ai_detection_score": ai["detection_score"],
        "ai_disclosure": ai["disclosure"],
        "watermark_applied": trust["watermark_applied"],
        "watermark_visible": trust["watermark_visible"],
        "watermark_invisible": trust["watermark_invisible"],
        "creator_name": identity["creator_name"],
        "copyright_owner": rights["copyright_owner"],
        "license_type": rights["license_type"],
        "registry_url": identity["registry_url"],
        "created_at": identity["created_at"],
        "file_size_bytes": identity["file_size_bytes"],
        "certificate_class": readiness["certificate_class"],
        "certificate_class_label": readiness["certificate_class_label"],
        "copyright_readiness": {
            "score": readiness["score"],
            "label": readiness["label"],
            "certificate_class": readiness["certificate_class"],
        },
        "humanproof": get_public_humanproof_summary(db, asset.omni_id),
        "legal_disclaimer": "Omni Veil provides provenance and authorship documentation infrastructure. Final copyright determinations are made by the applicable copyright authority.",
    }


@router.get("/assets/{omni_id}/report")
def get_report(
    omni_id: str,
    tenant: Client = Depends(resolve_tenant),
    db: Session = Depends(get_db),
):
    """Read an asset report without mutating verification counters."""
    asset = get_asset(db, omni_id, tenant.tenant_id)
    if not asset:
        raise HTTPException(404, "Asset not found")

    identity = asset_identity(asset)
    trust = trust_facts(asset)
    ai = ai_facts(asset)
    rights = ownership_facts(asset, asset.contributors)
    readiness = readiness_facts(asset)

    mime_type = asset.file_type or mimetypes.guess_type(asset.filename or "")[0]
    asset_type = asset.asset_type or ((mime_type or "file").split("/")[0])

    return {
        "omni_id": identity["omni_id"],
        "asset_id": identity["asset_id"],
        "filename": identity["filename"],
        "file_type": identity["file_type"],
        "mime_type": mime_type,
        "asset_type": asset_type,
        "sha256": identity["sha256"],
        "blake3": identity["blake3"],
        "phash": identity["phash"],
        "trust_score": trust["trust_score"],
        "content_label": trust["content_label"],
        "label_reasons": trust["label_reasons"],
        "ai_detection_score": ai["detection_score"],
        "ai_disclosure": ai["disclosure"],
        "watermark_applied": trust["watermark_applied"],
        "watermark_visible": trust["watermark_visible"],
        "watermark_invisible": trust["watermark_invisible"],
        "original_path": asset.original_path,
        "watermarked_path": asset.watermarked_path,
        "certificate_path": asset.certificate_path,
        "manifest_path": asset.manifest_path,
        "creator_name": identity["creator_name"],
        "copyright_owner": rights["copyright_owner"],
        "license_type": rights["license_type"],
        "file_size_bytes": identity["file_size_bytes"],
        "total_verifications": trust["total_verifications"],
        "created_at": identity["created_at"],
        "registry_url": identity["registry_url"],
        "humanproof": get_public_humanproof_summary(db, asset.omni_id),
        "copyright_readiness_score": readiness["score"],
        "copyright_readiness_label": readiness["label"],
        "certificate_class": readiness["certificate_class"],
        "certificate_class_label": readiness["certificate_class_label"],
        "human_authorship_evidence": human_authorship(asset),
        "ai_assisted_contributions": {
            "ai_tools_used": ai["declared_tools"],
            "ai_disclosure_complete": ai["disclosure_complete"],
            "ai_modification_by_human": ai["modification_by_human"],
        },
        "ownership_declarations": rights,
        "stored_facts": build_asset_facts(asset, asset.contributors),
    }


@router.get("/assets/{omni_id}/export")
def export_copyright_package(
    omni_id: str,
    tenant: Client = Depends(resolve_tenant),
    db: Session = Depends(get_db),
):
    asset = get_asset(db, omni_id, tenant.tenant_id)
    if not asset:
        raise HTTPException(404, "Asset not found")

    zip_bytes, filename = build_export_package(asset)
    return Response(
        content=zip_bytes,
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Content-Length": str(len(zip_bytes)),
        },
    )


@router.get("/assets/{omni_id}/copyright-report")
def get_copyright_report(
    omni_id: str,
    tenant: Client = Depends(resolve_tenant),
    db: Session = Depends(get_db),
):
    asset = get_asset(db, omni_id, tenant.tenant_id)
    if not asset:
        raise HTTPException(404, "Asset not found")
    return generate_copyright_readiness_report(asset)


@router.get("/assets/{omni_id}")
def get_asset_info(
    omni_id: str,
    tenant: Client = Depends(resolve_tenant),
    db: Session = Depends(get_db),
):
    asset = get_asset(db, omni_id, tenant.tenant_id)
    if not asset:
        raise HTTPException(404, "Asset not found")
    identity = asset_identity(asset)
    trust = trust_facts(asset)
    ai = ai_facts(asset)
    return {
        "omni_id": identity["omni_id"],
        "filename": identity["filename"],
        "asset_type": identity["asset_type"],
        "trust_score": trust["trust_score"],
        "content_label": trust["content_label"],
        "ai_disclosure": ai["disclosure"],
        "creator_name": identity["creator_name"],
        "created_at": identity["created_at"],
        "humanproof": get_public_humanproof_summary(db, asset.omni_id),
    }


def _certificate_item(certificate: Certificate) -> dict:
    asset = certificate.asset
    try:
        payload = json.loads(certificate.cert_json or "{}")
    except (json.JSONDecodeError, TypeError):
        payload = {}

    return {
        "cert_id": certificate.cert_id,
        "omni_id": certificate.omni_id,
        "filename": asset.filename if asset else None,
        "subject_name": certificate.subject_name,
        "issuer": certificate.issuer,
        "certificate_class": certificate.certificate_class,
        "certificate_class_label": payload.get("certificate_class_label"),
        "trust_score": asset.trust_score if asset else None,
        "content_label": asset.content_label if asset else None,
        "issued_at": certificate.issued_at.isoformat() if certificate.issued_at else None,
        "certificate_hash": certificate.certificate_hash,
        "signature_algorithm": payload.get("signature_algorithm"),
        "public_key_id": payload.get("public_key_id"),
    }


@router.get("/certificates")
def list_certificates(
    limit: int = 50,
    tenant: Client = Depends(resolve_tenant),
    db: Session = Depends(get_db),
):
    base_query = (
        db.query(Certificate)
        .join(Certificate.asset)
        .filter(Certificate.asset.has(tenant_id=tenant.tenant_id))
    )
    total_count = base_query.count()
    certificates = (
        base_query
        .order_by(Certificate.issued_at.desc())
        .limit(limit)
        .all()
    )
    items = [_certificate_item(certificate) for certificate in certificates]
    return {
        "items": items,
        "total": total_count,
        "total_count": total_count,
        "returned_count": len(items),
        "limit": limit,
    }


@router.get("/certificates/{cert_id}")
def get_certificate(
    cert_id: str,
    tenant: Client = Depends(resolve_tenant),
    db: Session = Depends(get_db),
):
    certificate = (
        db.query(Certificate)
        .join(Certificate.asset)
        .filter(
            Certificate.cert_id == cert_id,
            Certificate.asset.has(tenant_id=tenant.tenant_id),
        )
        .first()
    )
    if not certificate:
        raise HTTPException(404, "Certificate not found")

    item = _certificate_item(certificate)
    try:
        payload = json.loads(certificate.cert_json or "{}")
    except (json.JSONDecodeError, TypeError):
        payload = {}

    asset = certificate.asset
    facts = build_asset_facts(asset, asset.contributors)
    item.update({
        "certificate": payload,
        "asset": {
            "omni_id": facts["identity"]["omni_id"],
            "filename": facts["identity"]["filename"],
            "asset_type": facts["identity"]["asset_type"],
            "creator_name": facts["identity"]["creator_name"],
            "copyright_owner": facts["rights"]["copyright_owner"],
            "license_type": facts["rights"]["license_type"],
            "sha256": facts["identity"]["sha256"],
            "blake3": facts["identity"]["blake3"],
            "trust_score": facts["trust"]["trust_score"],
            "content_label": facts["trust"]["content_label"],
            "created_at": facts["identity"]["created_at"],
        },
        "stored_facts": facts,
        "humanproof": get_public_humanproof_summary(db, asset.omni_id),
    })
    return item
