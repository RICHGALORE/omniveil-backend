"""Cross-layer fact integrity checks for Omni Veil asset records.

This service compares persisted canonical facts with independent records produced
at ingest time. It does not decide legal ownership or authenticity. Its job is
to detect reporting drift between the database, signed certificate, provenance
manifest, contributor splits, and verification counters.
"""
from __future__ import annotations

import json
from typing import Any

from sqlalchemy.orm import Session

from app.core.storage import resolve_stored_path
from app.db.models import Asset, Certificate, VerificationLog
from app.services.asset_facts import build_asset_facts, percentage, text
from app.services.crypto_signing import verify_certificate_signature


INTEGRITY_VERSION = "1.0"
LEGAL_BOUNDARY = (
    "Fact integrity checks compare Omni Veil records for internal consistency. "
    "They do not determine legal ownership, copyright validity, originality, "
    "or authenticity by themselves."
)


def _same(left: Any, right: Any) -> bool:
    if isinstance(left, float) or isinstance(right, float):
        try:
            return abs(float(left) - float(right)) <= 0.0001
        except (TypeError, ValueError):
            return left == right
    return left == right


def _comparison(name: str, expected: Any, observed: Any) -> dict[str, Any]:
    return {
        "field": name,
        "match": _same(expected, observed),
        "expected": expected,
        "observed": observed,
    }


def _normalize_certificate_splits(payload: dict[str, Any]) -> list[dict[str, Any]]:
    section = payload.get("section_c_ownership_splits")
    if not isinstance(section, dict):
        return []
    raw = section.get("splits")
    if not isinstance(raw, list):
        return []

    rows: list[dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        ownership = item.get("ownership_split_pct")
        if ownership is None:
            ownership = item.get("split_percentage")
        rows.append({
            "owner_name": text(item.get("contributor_name") or item.get("name")),
            "role": text(item.get("role")),
            "ownership_split_pct": percentage(ownership),
            "creative_contribution_pct": percentage(item.get("creative_contribution_pct")),
            "ai_assisted_pct": percentage(item.get("ai_assisted_pct")),
        })
    return sorted(rows, key=lambda row: ((row.get("owner_name") or "").casefold(), row.get("role") or ""))


def _normalize_db_splits(facts: dict[str, Any]) -> list[dict[str, Any]]:
    rows = facts["rights"].get("ownership_splits") or []
    return sorted(
        [
            {
                "owner_name": text(row.get("owner_name")),
                "role": text(row.get("role")),
                "ownership_split_pct": percentage(row.get("ownership_split_pct")),
                "creative_contribution_pct": percentage(row.get("creative_contribution_pct")),
                "ai_assisted_pct": percentage(row.get("ai_assisted_pct")),
            }
            for row in rows
        ],
        key=lambda row: ((row.get("owner_name") or "").casefold(), row.get("role") or ""),
    )


def _load_latest_certificate(db: Session, omni_id: str) -> tuple[Certificate | None, dict[str, Any] | None]:
    certificate = (
        db.query(Certificate)
        .filter(Certificate.omni_id == omni_id)
        .order_by(Certificate.issued_at.desc())
        .first()
    )
    if not certificate:
        return None, None
    try:
        payload = json.loads(certificate.cert_json or "{}")
    except (json.JSONDecodeError, TypeError):
        return certificate, None
    return certificate, payload if isinstance(payload, dict) else None


def _certificate_check(db: Session, asset: Asset, facts: dict[str, Any]) -> dict[str, Any]:
    certificate, payload = _load_latest_certificate(db, asset.omni_id)
    if certificate is None:
        return {
            "name": "signed_certificate",
            "status": "unavailable",
            "detail": "No certificate record is stored for this asset.",
            "comparisons": [],
        }
    if payload is None:
        return {
            "name": "signed_certificate",
            "status": "fail",
            "detail": "Latest certificate record is not valid JSON.",
            "cert_id": certificate.cert_id,
            "comparisons": [],
        }

    identity = facts["identity"]
    rights = facts["rights"]
    ai = facts["ai"]
    metadata_lock = payload.get("metadata_lock")
    signature_valid = False
    if isinstance(metadata_lock, dict):
        try:
            signature_valid = verify_certificate_signature(payload, metadata_lock)
        except Exception:
            signature_valid = False

    comparisons = [
        _comparison("omni_id", identity["omni_id"], payload.get("omni_id")),
        _comparison("asset_id", identity["asset_id"], payload.get("asset_id")),
        _comparison("filename", identity["filename"], payload.get("filename")),
        _comparison("sha256", identity["sha256"], payload.get("sha256")),
        _comparison("blake3", identity["blake3"], payload.get("blake3")),
        _comparison("creator_name", identity["creator_name"], text(payload.get("subject_name"))),
        _comparison("copyright_owner", rights["copyright_owner"], text(payload.get("copyright_owner"))),
        _comparison("license_type", rights["license_type"], text(payload.get("license_type"))),
        _comparison("ai_disclosure", ai["disclosure"], text(payload.get("ai_disclosure"))),
        _comparison(
            "ownership_splits",
            _normalize_db_splits(facts),
            _normalize_certificate_splits(payload),
        ),
    ]

    if isinstance(metadata_lock, dict):
        comparisons.extend([
            _comparison("metadata_lock.omni_id", identity["omni_id"], metadata_lock.get("omni_id")),
            _comparison("metadata_lock.asset_id", identity["asset_id"], metadata_lock.get("asset_id")),
            _comparison("metadata_lock.sha256", identity["sha256"], metadata_lock.get("sha256")),
            _comparison("metadata_lock.blake3", identity["blake3"], metadata_lock.get("blake3")),
            _comparison("metadata_lock.creator_name", identity["creator_name"], text(metadata_lock.get("creator_name"))),
            _comparison("metadata_lock.copyright_owner", rights["copyright_owner"], text(metadata_lock.get("copyright_owner"))),
            _comparison("metadata_lock.license_type", rights["license_type"], text(metadata_lock.get("license_type"))),
            _comparison("metadata_lock.ai_disclosure", ai["disclosure"], text(metadata_lock.get("ai_disclosure"))),
        ])

    failed = [item for item in comparisons if not item["match"]]
    if not signature_valid:
        failed.append({
            "field": "signature",
            "match": False,
            "expected": "valid Ed25519 signature over stored metadata lock",
            "observed": "invalid or unavailable",
        })

    return {
        "name": "signed_certificate",
        "status": "fail" if failed else "pass",
        "detail": (
            f"{len(failed)} certificate consistency issue(s) found."
            if failed
            else "Signed certificate and metadata lock match canonical stored facts."
        ),
        "cert_id": certificate.cert_id,
        "signature_valid": signature_valid,
        "comparisons": comparisons,
        "mismatches": failed,
    }


def _manifest_check(asset: Asset, facts: dict[str, Any]) -> dict[str, Any]:
    path = resolve_stored_path(asset.manifest_path)
    if path is None or not path.exists():
        return {
            "name": "provenance_manifest",
            "status": "unavailable",
            "detail": "No readable provenance manifest is available at the stored path.",
            "comparisons": [],
        }
    try:
        payload = json.loads(path.read_text())
    except Exception:
        return {
            "name": "provenance_manifest",
            "status": "fail",
            "detail": "Stored provenance manifest is unreadable or invalid JSON.",
            "comparisons": [],
        }
    if not isinstance(payload, dict):
        return {
            "name": "provenance_manifest",
            "status": "fail",
            "detail": "Stored provenance manifest is not a JSON object.",
            "comparisons": [],
        }

    identity = facts["identity"]
    rights = facts["rights"]
    ai = facts["ai"]
    trust = facts["trust"]
    comparisons = [
        _comparison("omni_id", identity["omni_id"], payload.get("omni_id")),
        _comparison("asset_id", identity["asset_id"], payload.get("asset_id")),
        _comparison("filename", identity["filename"], payload.get("filename")),
        _comparison("sha256", identity["sha256"], payload.get("sha256")),
        _comparison("blake3", identity["blake3"], payload.get("blake3")),
        _comparison("phash", identity["phash"], payload.get("phash")),
        _comparison("creator_name", identity["creator_name"], text(payload.get("creator_name"))),
        _comparison("copyright_owner", rights["copyright_owner"], text(payload.get("copyright_owner"))),
        _comparison("license_type", rights["license_type"], text(payload.get("license_type"))),
        _comparison("ai_disclosure", ai["disclosure"], text(payload.get("ai_disclosure"))),
        _comparison("trust_score", trust["trust_score"], payload.get("trust_score")),
        _comparison("content_label", trust["content_label"], payload.get("content_label")),
    ]
    failed = [item for item in comparisons if not item["match"]]
    return {
        "name": "provenance_manifest",
        "status": "fail" if failed else "pass",
        "detail": (
            f"{len(failed)} manifest consistency issue(s) found."
            if failed
            else "Stored provenance manifest matches canonical stored facts."
        ),
        "comparisons": comparisons,
        "mismatches": failed,
    }


def _verification_counter_check(db: Session, asset: Asset, facts: dict[str, Any]) -> dict[str, Any]:
    log_count = (
        db.query(VerificationLog)
        .filter(
            VerificationLog.omni_id == asset.omni_id,
            VerificationLog.check_type.in_(["file_hash", "omni_id"]),
        )
        .count()
    )
    stored_count = facts["trust"]["total_verifications"]
    match = stored_count == log_count
    return {
        "name": "verification_counter",
        "status": "pass" if match else "fail",
        "detail": (
            "Stored verification count matches asset-linked verification logs."
            if match
            else "Stored verification count does not match asset-linked verification logs."
        ),
        "stored_total_verifications": stored_count,
        "matching_log_count": log_count,
    }


def build_fact_integrity_report(db: Session, asset: Asset) -> dict[str, Any]:
    facts = build_asset_facts(asset, asset.contributors)
    checks = [
        _certificate_check(db, asset, facts),
        _manifest_check(asset, facts),
        _verification_counter_check(db, asset, facts),
    ]

    failed = [check for check in checks if check["status"] == "fail"]
    unavailable = [check for check in checks if check["status"] == "unavailable"]
    status = "review_required" if failed else "incomplete" if unavailable else "consistent"

    return {
        "integrity_version": INTEGRITY_VERSION,
        "omni_id": asset.omni_id,
        "status": status,
        "mismatch_count": len(failed),
        "unavailable_count": len(unavailable),
        "checks": checks,
        "stored_facts": facts,
        "legal_boundary": LEGAL_BOUNDARY,
    }
