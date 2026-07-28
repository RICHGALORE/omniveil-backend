"""
Metadata Intelligence — Commit 2: persistence service.

A dedicated, independent layer that persists the output of the stateless
extraction service (``app.services.metadata_extraction``) into the durable
``asset_metadata`` table. The upload endpoint calls into this module rather
than embedding persistence logic inline.

Scope is persistence ONLY. This module does not extract metadata itself, does
not touch registry / certificates / verify / trust / anomaly detection, and
does not modify the legacy ``assets.metadata_json`` blob.

Three layers are stored side-by-side:

  * raw        — exact extractor output (``raw_metadata``) where practical
  * normalized — the canonical Omni Veil sections
  * derived    — values computed by Omni Veil (engine identity, extractor
                 flags, warnings, timing, deterministic metadata SHA-256)
"""
from __future__ import annotations

import hashlib
import json
import logging
import uuid
from datetime import datetime
from typing import Any, Dict, Optional

from sqlalchemy.orm import Session

from app.db.models import AssetMetadata
from app.services.metadata_extraction import ENGINE_NAME, ENGINE_VERSION

logger = logging.getLogger("omniveil.metadata.persistence")

# Canonical normalized sections persisted in ``normalized_metadata_json``.
# ``location`` is retained as a backward-compatible alias of ``gps``.
NORMALIZED_SECTIONS = (
    "file", "technical", "codec", "container", "timestamps", "camera",
    "gps", "location", "copyright", "software", "audio_tags",
    "exif", "iptc", "xmp", "hashes",
)

# Envelope fields computed by Omni Veil, persisted in ``derived_metadata_json``.
_DERIVED_ENVELOPE = ("extractor", "exiftool_available", "supported",
                     "warnings", "duration_ms")


def _canonical_json(obj: Any) -> str:
    """Deterministic JSON: sorted keys, compact separators, stable str fallback."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def compute_metadata_sha256(normalized: Dict[str, Any]) -> str:
    """SHA-256 over the canonical (sorted) normalized-metadata JSON.

    Deterministic: identical normalized content always yields the same digest,
    independent of dict ordering.
    """
    return hashlib.sha256(_canonical_json(normalized).encode("utf-8")).hexdigest()


def split_layers(extraction: Dict[str, Any]) -> tuple[dict, dict, dict]:
    """Partition a raw extraction result into (raw, normalized, derived)."""
    raw = extraction.get("raw_metadata", {}) or {}
    normalized = {k: extraction.get(k) for k in NORMALIZED_SECTIONS}
    derived: Dict[str, Any] = {k: extraction.get(k) for k in _DERIVED_ENVELOPE}
    derived["engine_name"] = ENGINE_NAME
    derived["engine_version"] = ENGINE_VERSION
    derived["metadata_sha256"] = compute_metadata_sha256(normalized)
    return raw, normalized, derived


def _apply(record: AssetMetadata, *, asset_id: str, tenant_id: Optional[str],
           omni_id: Optional[str], extraction: Dict[str, Any],
           raw: dict, normalized: dict, derived: dict, now: datetime) -> None:
    record.asset_id = asset_id
    record.tenant_id = tenant_id
    record.omni_id = omni_id
    record.engine_name = ENGINE_NAME
    record.engine_version = ENGINE_VERSION
    record.extractor = extraction.get("extractor")
    record.exiftool_available = bool(extraction.get("exiftool_available"))
    record.supported = bool(extraction.get("supported"))
    record.raw_metadata_json = _canonical_json(raw)
    record.normalized_metadata_json = _canonical_json(normalized)
    record.derived_metadata_json = _canonical_json(derived)
    record.warnings_json = _canonical_json(extraction.get("warnings", []) or [])
    record.metadata_sha256 = derived["metadata_sha256"]
    duration = extraction.get("duration_ms")
    record.extraction_duration_ms = float(duration) if duration is not None else None
    record.analyzed_at = now
    record.updated_at = now


def persist_asset_metadata(
    db: Session,
    *,
    asset_id: str,
    tenant_id: Optional[str],
    omni_id: Optional[str],
    extraction: Dict[str, Any],
) -> AssetMetadata:
    """
    Create or update the single metadata record for an asset.

    Deterministic upsert:
      1. If a record already exists for ``asset_id`` -> update it.
      2. Else if a record exists for the same ``(omni_id, tenant_id)`` identity
         (e.g. a re-upload of identical content that produced a new asset_id)
         -> update it, re-pointing ``asset_id``.
      3. Otherwise -> create a new record.

    This guarantees one durable metadata record per asset identity and makes
    re-analysis update in place rather than creating uncontrolled duplicates.
    Commits the session; rolls back and re-raises on failure.
    """
    raw, normalized, derived = split_layers(extraction)
    now = datetime.utcnow()

    try:
        record = (
            db.query(AssetMetadata)
            .filter(AssetMetadata.asset_id == asset_id)
            .first()
        )
        if record is None and omni_id is not None:
            record = (
                db.query(AssetMetadata)
                .filter(
                    AssetMetadata.omni_id == omni_id,
                    AssetMetadata.tenant_id == tenant_id,
                )
                .first()
            )

        action = "updated"
        if record is None:
            record = AssetMetadata(id=str(uuid.uuid4()), created_at=now)
            action = "created"
            db.add(record)

        _apply(record, asset_id=asset_id, tenant_id=tenant_id, omni_id=omni_id,
               extraction=extraction, raw=raw, normalized=normalized,
               derived=derived, now=now)

        db.commit()
        db.refresh(record)
        logger.info(
            "Metadata persisted (%s): omni_id=%s asset_id=%s tenant=%s "
            "extractor=%s sha256=%s duration_ms=%s",
            action, omni_id, asset_id, tenant_id, record.extractor,
            record.metadata_sha256, record.extraction_duration_ms,
        )
        return record
    except Exception as exc:
        db.rollback()
        logger.error(
            "Metadata persistence FAILED: omni_id=%s asset_id=%s tenant=%s err=%s",
            omni_id, asset_id, tenant_id, exc,
        )
        raise


# ── Read helpers (tenant-isolated) ────────────────────────────────────────────

def get_metadata_by_asset_id(
    db: Session, asset_id: str, tenant_id: Optional[str] = None
) -> Optional[AssetMetadata]:
    q = db.query(AssetMetadata).filter(AssetMetadata.asset_id == asset_id)
    if tenant_id is not None:
        q = q.filter(AssetMetadata.tenant_id == tenant_id)
    return q.first()


def get_metadata_by_omni_id(
    db: Session, omni_id: str, tenant_id: Optional[str] = None
) -> Optional[AssetMetadata]:
    q = db.query(AssetMetadata).filter(AssetMetadata.omni_id == omni_id)
    if tenant_id is not None:
        q = q.filter(AssetMetadata.tenant_id == tenant_id)
    return q.first()


def serialize_record(record: AssetMetadata) -> Dict[str, Any]:
    """Serialize a persisted record into a JSON-safe API response dict,
    re-hydrating the three stored JSON layers."""
    def _load(blob: Optional[str], default):
        if not blob:
            return default
        try:
            return json.loads(blob)
        except Exception:
            return default

    return {
        "id": record.id,
        "asset_id": record.asset_id,
        "omni_id": record.omni_id,
        "tenant_id": record.tenant_id,
        "engine_name": record.engine_name,
        "engine_version": record.engine_version,
        "extractor": record.extractor,
        "exiftool_available": record.exiftool_available,
        "supported": record.supported,
        "metadata_sha256": record.metadata_sha256,
        "extraction_duration_ms": record.extraction_duration_ms,
        "raw_metadata": _load(record.raw_metadata_json, {}),
        "normalized_metadata": _load(record.normalized_metadata_json, {}),
        "derived_metadata": _load(record.derived_metadata_json, {}),
        "warnings": _load(record.warnings_json, []),
        "analyzed_at": record.analyzed_at.isoformat() if record.analyzed_at else None,
        "created_at": record.created_at.isoformat() if record.created_at else None,
        "updated_at": record.updated_at.isoformat() if record.updated_at else None,
    }
