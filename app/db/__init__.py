"""
app.db — database package.

Exports the session helpers and backward-compatible CRUD functions so that
existing endpoint imports (`from app.db import get_db, save_asset, …`) keep
working without changes.
"""

from app.db.session import get_db, init_db, engine, SessionLocal  # noqa: F401
from app.db.models import (  # noqa: F401
    Asset,
    ProvenanceEvent,
    Certificate,
    Contributor,
    LiveSplitSession,
    VerificationLog,
    Client,
    AssetMetadata,
)
import json


# ---------------------------------------------------------------------------
# Backward-compatible CRUD helpers (used by registry.py and ingest.py)
# ---------------------------------------------------------------------------

def save_asset(db, data: dict) -> Asset:
    asset = Asset(
        omni_id=data["omni_id"],
        asset_id=data.get("asset_id", ""),
        filename=data.get("filename", data.get("original_filename", "")),
        file_type=data.get("mime_type", "application/octet-stream"),
        original_path=data.get("original_path", ""),
        watermarked_path=data.get("watermarked_path"),
        certificate_path=data.get("certificate_path"),
        manifest_path=data.get("manifest_path"),
        sha256=data.get("sha256", ""),
        blake3=data.get("blake3", ""),
        phash=data.get("phash"),
        trust_score=data.get("trust_score", 0.5),
        content_label=data.get("content_label", "unverified"),
        label_reasons=json.dumps(data.get("label_reasons", [])),
        ai_detection_score=data.get("ai_detection_score"),
        ai_disclosure=data.get("ai_disclosure"),
        watermark_applied=data.get("watermark_applied", False),
        watermark_visible=data.get("watermark_visible", False),
        watermark_invisible=data.get("watermark_invisible", False),
        asset_type=data.get("asset_type", "file"),
        file_size_bytes=data.get("file_size_bytes"),
        creator_name=data.get("creator_name"),
        copyright_owner=data.get("copyright_owner"),
        license_type=data.get("license_type"),
        total_verifications=0,
        registry_url=data.get("registry_url", ""),
        metadata_json=data.get("metadata_json"),
        # ── Human Authorship Evidence ──────────────────────────────────────────
        human_creative_direction=data.get("human_creative_direction"),
        human_editing_present=data.get("human_editing_present"),
        human_arrangement_present=data.get("human_arrangement_present"),
        human_lyrics_present=data.get("human_lyrics_present"),
        human_performance_present=data.get("human_performance_present"),
        human_transformation_present=data.get("human_transformation_present"),
        # ── Copyright Readiness ────────────────────────────────────────────────
        copyright_readiness_score=data.get("copyright_readiness_score"),
        copyright_readiness_label=data.get("copyright_readiness_label"),
        ai_disclosure_complete=data.get("ai_disclosure_complete"),
        ai_tools_used_json=data.get("ai_tools_used_json"),
        ai_modification_by_human=data.get("ai_modification_by_human"),
        human_authorship_summary=data.get("human_authorship_summary"),
    )
    db.merge(asset)
    db.commit()
    return asset


def get_asset(db, omni_id: str) -> Asset | None:
    return db.query(Asset).filter(Asset.omni_id == omni_id).first()


def get_all_assets(db, limit: int = 50) -> list[Asset]:
    return db.query(Asset).order_by(Asset.created_at.desc()).limit(limit).all()
