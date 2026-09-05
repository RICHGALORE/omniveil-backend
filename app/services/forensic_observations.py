"""Persistence helpers for provider-separated forensic observations."""
from __future__ import annotations

import json
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from app.db.forensic_models import ForensicObservation


def _safe_details(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    try:
        encoded = json.dumps(value, separators=(",", ":"), sort_keys=True)
        decoded = json.loads(encoded)
        return decoded if isinstance(decoded, dict) else {}
    except (TypeError, ValueError):
        return {}


def persist_forensic_observations(
    db: Session,
    *,
    omni_id: str,
    tenant_id: str,
    observations: list[dict[str, Any]],
    observed_at: datetime | None = None,
) -> list[ForensicObservation]:
    """Append normalized provider observations without rewriting prior runs."""
    rows: list[ForensicObservation] = []
    timestamp = observed_at or datetime.utcnow()

    for observation in observations:
        provider = str(observation.get("provider") or "").strip().lower()
        model = str(observation.get("model") or "").strip()
        signal = str(observation.get("signal") or "").strip()
        if not provider or not model or not signal:
            continue
        try:
            probability = float(observation.get("probability"))
        except (TypeError, ValueError):
            continue
        probability = max(0.0, min(1.0, probability))

        row = ForensicObservation(
            observation_id=str(uuid.uuid4()),
            omni_id=omni_id,
            tenant_id=tenant_id,
            provider=provider,
            model=model,
            signal=signal,
            probability=probability,
            status=str(observation.get("status") or "available"),
            details_json=json.dumps(
                _safe_details(observation.get("details")),
                separators=(",", ":"),
                sort_keys=True,
            ),
            observed_at=timestamp,
        )
        db.add(row)
        rows.append(row)

    if rows:
        db.commit()
    return rows


def _row_to_dict(row: ForensicObservation) -> dict[str, Any]:
    try:
        details = json.loads(row.details_json or "{}")
    except (json.JSONDecodeError, TypeError):
        details = {}
    if not isinstance(details, dict):
        details = {}
    return {
        "observation_id": row.observation_id,
        "provider": row.provider,
        "model": row.model,
        "signal": row.signal,
        "probability": row.probability,
        "status": row.status,
        "details": details,
        "observed_at": row.observed_at.isoformat() + "Z" if row.observed_at else None,
    }


def get_forensic_observations(
    db: Session,
    *,
    omni_id: str,
    tenant_id: str,
    latest_only: bool = True,
) -> list[dict[str, Any]]:
    """Return tenant-owned observations.

    Current OmniSpectra/Evidence Graph views default to the latest observation
    for each provider+model+signal tuple so an older model run cannot keep a
    stale high/low score in the current verdict. The database remains append-only.
    """
    rows = (
        db.query(ForensicObservation)
        .filter(
            ForensicObservation.omni_id == omni_id,
            ForensicObservation.tenant_id == tenant_id,
        )
        .order_by(ForensicObservation.observed_at.desc(), ForensicObservation.observation_id.desc())
        .all()
    )

    if latest_only:
        selected: list[ForensicObservation] = []
        seen: set[tuple[str, str, str]] = set()
        for row in rows:
            key = (row.provider, row.model, row.signal)
            if key in seen:
                continue
            seen.add(key)
            selected.append(row)
        rows = list(reversed(selected))
    else:
        rows = list(reversed(rows))

    return [_row_to_dict(row) for row in rows]
