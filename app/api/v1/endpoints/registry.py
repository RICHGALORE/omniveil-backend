from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy.orm import Session
import json

from app.core.tenant import resolve_tenant
from app.db.session import get_db
from app.db.models import Client
from app.db import get_asset, get_all_assets
from app.services.copyright_report import generate_copyright_readiness_report
from app.services.export_package import build_export_package

router = APIRouter()


@router.get("/assets")
def list_assets(
    limit: int = 50,
    tenant: Client = Depends(resolve_tenant),
    db: Session = Depends(get_db),
):
    assets = get_all_assets(db, limit)
    return {
        "items": [
            {
                "omni_id": a.omni_id,
                "filename": a.filename,
                "asset_type": a.asset_type,
                "file_type": a.file_type,
                "trust_score": a.trust_score,
                "content_label": a.content_label,
                "creator_name": a.creator_name,
                "ai_disclosure": a.ai_disclosure,
                "created_at": a.created_at.isoformat() if a.created_at else None,
                "total_verifications": a.total_verifications,
            }
            for a in assets
        ],
        "total": len(assets),
    }



@router.get("/registry/assets/{omni_id}")
def get_public_registry_asset(
    omni_id: str,
    db: Session = Depends(get_db),
):
    """
    Public registry lookup endpoint.

    This powers registry_url links generated during upload:
    /api/v1/registry/assets/{omni_id}
    """
    asset = get_asset(db, omni_id)
    if not asset:
        raise HTTPException(404, "Asset not found")

    return {
        "omni_id": asset.omni_id,
        "asset_id": asset.asset_id,
        "filename": asset.filename,
        "sha256": asset.sha256,
        "blake3": asset.blake3,
        "phash": asset.phash,
        "trust_score": asset.trust_score,
        "content_label": asset.content_label,
        "label_reasons": json.loads(asset.label_reasons or "[]"),
        "ai_detection_score": asset.ai_detection_score,
        "ai_disclosure": asset.ai_disclosure,
        "watermark_applied": asset.watermark_applied,
        "watermark_visible": asset.watermark_visible,
        "watermark_invisible": asset.watermark_invisible,
        "creator_name": asset.creator_name,
        "copyright_owner": asset.copyright_owner,
        "license_type": asset.license_type,
        "original_path": asset.original_path,
        "watermarked_path": asset.watermarked_path,
        "certificate_path": asset.certificate_path,
        "manifest_path": asset.manifest_path,
        "registry_url": asset.registry_url,
        "created_at": asset.created_at.isoformat() if asset.created_at else None,
        "file_size_bytes": asset.file_size_bytes,
        "certificate_class": asset.certificate_class,
        "certificate_class_label": asset.certificate_class_label,
        "copyright_readiness": {
            "score": asset.copyright_readiness_score,
            "label": asset.copyright_readiness_label,
            "certificate_class": asset.certificate_class,
        },
        "legal_disclaimer": "Omni Veil provides provenance and authorship documentation infrastructure. Final copyright determinations are made by the applicable copyright authority.",
    }


@router.get("/assets/{omni_id}/report")
def get_report(
    omni_id: str,
    tenant: Client = Depends(resolve_tenant),
    db: Session = Depends(get_db),
):
    asset = get_asset(db, omni_id)
    if not asset:
        raise HTTPException(404, "Asset not found")

    asset.total_verifications += 1
    db.commit()

    ai_tools: list = []
    if asset.ai_tools_used_json:
        try:
            ai_tools = json.loads(asset.ai_tools_used_json)
        except (json.JSONDecodeError, TypeError):
            ai_tools = []

    return {
        "omni_id": asset.omni_id,
        "asset_id": asset.asset_id,
        "filename": asset.filename,
        "file_type": asset.file_type,
        "mime_type": asset.mime_type,
        "asset_type": asset.asset_type,
        "sha256": asset.sha256,
        "blake3": asset.blake3,
        "phash": asset.phash,
        "trust_score": asset.trust_score,
        "content_label": asset.content_label,
        "label_reasons": json.loads(asset.label_reasons or "[]"),
        "ai_detection_score": asset.ai_detection_score,
        "ai_disclosure": asset.ai_disclosure,
        "watermark_applied": asset.watermark_applied,
        "watermark_visible": asset.watermark_visible,
        "watermark_invisible": asset.watermark_invisible,
        "original_path": asset.original_path,
        "watermarked_path": asset.watermarked_path,
        "certificate_path": asset.certificate_path,
        "manifest_path": asset.manifest_path,
        "creator_name": asset.creator_name,
        "copyright_owner": asset.copyright_owner,
        "license_type": asset.license_type,
        "file_size_bytes": asset.file_size_bytes,
        "total_verifications": asset.total_verifications,
        "created_at": asset.created_at.isoformat() if asset.created_at else None,
        "registry_url": asset.registry_url,
        # ── Copyright readiness ──────────────────────────────────────────────
        "copyright_readiness_score": asset.copyright_readiness_score,
        "copyright_readiness_label": asset.copyright_readiness_label,
        "human_authorship_evidence": {
            "creative_direction": asset.human_creative_direction,
            "editing": asset.human_editing_present,
            "arrangement": asset.human_arrangement_present,
            "lyrics": asset.human_lyrics_present,
            "performance": asset.human_performance_present,
            "transformation": asset.human_transformation_present,
            "summary": asset.human_authorship_summary,
        },
        "ai_assisted_contributions": {
            "ai_tools_used": ai_tools,
            "ai_disclosure_complete": asset.ai_disclosure_complete,
            "ai_modification_by_human": asset.ai_modification_by_human,
        },
    }


@router.get("/assets/{omni_id}/export")
def export_copyright_package(
    omni_id: str,
    tenant: Client = Depends(resolve_tenant),
    db: Session = Depends(get_db),
):
    """
    Download a ZIP copyright export package for an asset.

    Contains: certificate.json, provenance_manifest.json,
    contributor_declarations.json, workflow_analysis.json,
    timestamps.json, audit_history.json, authorship_summary.json, README.txt

    Omni Veil provides provenance and authorship documentation infrastructure.
    Final copyright determinations are made by the applicable copyright authority.
    """
    asset = get_asset(db, omni_id)
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
    """
    Generate a full Copyright Readiness Report for an asset.

    Contains human contributors, AI tools, workflow lineage, transformation
    chain, timestamps, contributor declarations, ownership declarations,
    provenance continuity score, and the required legal disclaimer.

    Omni Veil provides provenance and authorship documentation infrastructure.
    Final copyright determinations are made by the applicable copyright authority.
    """
    asset = get_asset(db, omni_id)
    if not asset:
        raise HTTPException(404, "Asset not found")

    return generate_copyright_readiness_report(asset)


@router.get("/assets/{omni_id}")
def get_asset_info(
    omni_id: str,
    tenant: Client = Depends(resolve_tenant),
    db: Session = Depends(get_db),
):
    asset = get_asset(db, omni_id)
    if not asset:
        raise HTTPException(404, "Asset not found")
    return {
        "omni_id": asset.omni_id,
        "filename": asset.filename,
        "asset_type": asset.asset_type,
        "trust_score": asset.trust_score,
        "content_label": asset.content_label,
        "ai_disclosure": asset.ai_disclosure,
        "creator_name": asset.creator_name,
        "created_at": asset.created_at.isoformat() if asset.created_at else None,
    }
