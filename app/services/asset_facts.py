"""Canonical stored-fact projection for Omni Veil reporting.

Reporting code must read facts from persisted records without inventing fallback
ownership, authorship, AI status, percentages, identifiers, or counts. This
module centralizes the zero-safe/None-safe rules used by registry, reports,
exports, Evidence Graph, and verification surfaces.
"""
from __future__ import annotations

import json
from typing import Any, Iterable


def iso(value: Any) -> str | None:
    return value.isoformat() if value else None


def text(value: Any) -> str | None:
    if value is None:
        return None
    normalized = str(value).strip()
    return normalized or None


def json_list(value: str | None) -> list:
    if not value:
        return []
    try:
        parsed = json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return []
    return parsed if isinstance(parsed, list) else []


def percentage(primary: Any, legacy: Any = None) -> float | None:
    """Return a percentage without treating a legitimate 0 as missing."""
    value = primary if primary is not None else legacy
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def human_authorship(asset) -> dict:
    return {
        "creative_direction": asset.human_creative_direction,
        "editing": asset.human_editing_present,
        "arrangement": asset.human_arrangement_present,
        "lyrics": asset.human_lyrics_present,
        "performance": asset.human_performance_present,
        "transformation": asset.human_transformation_present,
        "summary": text(asset.human_authorship_summary),
    }


def ai_facts(asset) -> dict:
    return {
        "disclosure": text(asset.ai_disclosure),
        "disclosure_complete": asset.ai_disclosure_complete,
        "declared_tools": json_list(asset.ai_tools_used_json),
        "modification_by_human": asset.ai_modification_by_human,
        "detection_score": asset.ai_detection_score,
        "detection_pct": (
            round(float(asset.ai_detection_score) * 100, 1)
            if asset.ai_detection_score is not None
            else None
        ),
    }


def contributor_fact(contributor) -> dict:
    return {
        "contributor_id": contributor.contributor_id,
        "name": text(contributor.contributor_name),
        "role": text(contributor.role),
        "contribution_type": text(contributor.contribution_type),
        "creative_contribution_pct": percentage(
            contributor.creative_contribution_pct
        ),
        "ownership_split_pct": percentage(
            contributor.ownership_split_pct,
            contributor.split_percentage,
        ),
        "ai_assisted_pct": percentage(contributor.ai_assisted_pct),
        "added_at": iso(contributor.added_at),
    }


def contributor_facts(contributors: Iterable) -> list[dict]:
    return [contributor_fact(contributor) for contributor in contributors]


def ownership_facts(asset, contributors: Iterable = ()) -> dict:
    """Return explicit rights declarations only.

    Creator attribution never implies copyright ownership. A contributor row is
    included as an ownership split only when an ownership percentage is stored.
    """
    rows = []
    for contributor in contributor_facts(contributors):
        if contributor["ownership_split_pct"] is None:
            continue
        rows.append({
            "owner_name": contributor["name"],
            "role": contributor["role"],
            "ownership_split_pct": contributor["ownership_split_pct"],
            "creative_contribution_pct": contributor["creative_contribution_pct"],
            "ai_assisted_pct": contributor["ai_assisted_pct"],
        })

    total = None
    if rows:
        total = round(sum(row["ownership_split_pct"] for row in rows), 4)

    return {
        "copyright_owner": text(asset.copyright_owner),
        "license_type": text(asset.license_type),
        "ownership_splits": rows,
        "ownership_total_pct": total,
        "ownership_declared": bool(text(asset.copyright_owner) or rows),
    }


def asset_identity(asset) -> dict:
    return {
        "omni_id": asset.omni_id,
        "asset_id": asset.asset_id,
        "filename": asset.filename,
        "file_type": asset.file_type,
        "asset_type": asset.asset_type,
        "file_size_bytes": asset.file_size_bytes,
        "sha256": asset.sha256,
        "blake3": asset.blake3,
        "phash": asset.phash,
        "creator_name": text(asset.creator_name),
        "created_at": iso(asset.created_at),
        "registry_url": text(asset.registry_url),
    }


def trust_facts(asset) -> dict:
    try:
        reasons = json.loads(asset.label_reasons or "[]")
    except (json.JSONDecodeError, TypeError):
        reasons = []
    if not isinstance(reasons, list):
        reasons = []
    return {
        "trust_score": asset.trust_score,
        "content_label": asset.content_label,
        "label_reasons": reasons,
        "total_verifications": int(asset.total_verifications or 0),
        "watermark_applied": asset.watermark_applied,
        "watermark_visible": asset.watermark_visible,
        "watermark_invisible": asset.watermark_invisible,
    }


def readiness_facts(asset) -> dict:
    evidence = human_authorship(asset)
    confirmed = sum(
        1
        for key, value in evidence.items()
        if key != "summary" and value is True
    )
    return {
        "score": asset.copyright_readiness_score,
        "label": asset.copyright_readiness_label,
        "certificate_class": asset.certificate_class,
        "certificate_class_label": asset.certificate_class_label,
        "human_authorship_evidence": evidence,
        "confirmed_human_authorship_forms": confirmed,
    }


def build_asset_facts(asset, contributors: Iterable = ()) -> dict:
    """Single canonical projection for persisted asset facts."""
    return {
        "identity": asset_identity(asset),
        "trust": trust_facts(asset),
        "ai": ai_facts(asset),
        "rights": ownership_facts(asset, contributors),
        "copyright_readiness": readiness_facts(asset),
    }
