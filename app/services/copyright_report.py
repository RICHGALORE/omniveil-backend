"""
Copyright Readiness Report Generator — Omni Veil Authorship Support Infrastructure

Produces a structured report from an Asset record and its provenance relationships.
The report is the human-readable companion to the certificate — it narrates the
full creative provenance chain rather than just asserting the result.

REQUIRED LEGAL DISCLAIMER appears on every report.
"""

import json
import uuid
from datetime import datetime, timezone
from typing import Optional

from app.services.copyright_readiness import LEGAL_DISCLAIMER

# ── Provenance continuity scoring weights ──────────────────────────────────────
_CONTINUITY_WEIGHTS = {
    "upload_event":        0.20,
    "certificate_event":   0.20,
    "all_hashes":          0.15,   # sha256 + blake3 + phash
    "watermark_event":     0.10,
    "manifest_present":    0.10,
    "ownership_declared":  0.10,
    "event_integrity":     0.10,   # all events carry a non-empty event_hash
    "chain_continuous":    0.05,   # events timestamp-ordered with no backwards jumps
}


# ── Public entry point ─────────────────────────────────────────────────────────

def generate_copyright_readiness_report(asset) -> dict:
    """
    Build a Copyright Readiness Report from a fully-loaded Asset ORM object.

    `asset` must have `.provenance_events`, `.certificates`, and `.contributors`
    already loaded (SQLAlchemy lazy-loading is fine if a DB session is open).
    """
    now = datetime.now(timezone.utc).isoformat()
    report_id = str(uuid.uuid4())

    events = sorted(asset.provenance_events, key=lambda e: e.timestamp)
    certs  = sorted(asset.certificates,      key=lambda c: c.issued_at)
    contribs = list(asset.contributors)

    return {
        "report_id": report_id,
        "report_type": "copyright_readiness_report",
        "report_version": "1.0",
        "omni_id": asset.omni_id,
        "generated_at": now,

        # ── 1. Human contributors and roles ───────────────────────────────────
        "human_contributors": _build_contributors_section(asset, contribs),

        # ── 2. AI tools used and where ────────────────────────────────────────
        "ai_tools": _build_ai_tools_section(asset),

        # ── 3. Workflow lineage ───────────────────────────────────────────────
        "workflow_lineage": _build_workflow_lineage(events),

        # ── 4. Transformation chain ───────────────────────────────────────────
        "transformation_chain": _build_transformation_chain(asset, events),

        # ── 5. Timestamps ─────────────────────────────────────────────────────
        "timestamps": _build_timestamps(asset, events, certs),

        # ── 6. Contributor declarations ───────────────────────────────────────
        "contributor_declarations": _build_contributor_declarations(asset, contribs),

        # ── 7. Ownership declarations ─────────────────────────────────────────
        "ownership_declarations": _build_ownership_declarations(asset, contribs, certs),

        # ── 8. Copyright readiness ────────────────────────────────────────────
        "copyright_readiness": _build_readiness_section(asset),

        # ── 9. Provenance continuity score ────────────────────────────────────
        "provenance_continuity": _compute_provenance_continuity(asset, events, certs),

        # ── Required legal disclaimer ──────────────────────────────────────────
        "legal_disclaimer": LEGAL_DISCLAIMER,
    }


# ── Section builders ───────────────────────────────────────────────────────────

def _build_contributors_section(asset, contribs: list) -> list:
    """
    All human contributors with their documented roles.
    Falls back to the asset's creator_name if no Contributor rows exist.
    """
    if contribs:
        return [
            {
                "contributor_name": c.contributor_name,
                "role": c.role,
                "contribution_type": c.contribution_type,
                "creative_contribution_pct": c.creative_contribution_pct,
                "ownership_split_pct": (
                    c.ownership_split_pct or c.split_percentage
                ),
                "ai_assisted_pct": c.ai_assisted_pct,
                "wallet_address": c.wallet_address,
                "added_at": c.added_at.isoformat() if c.added_at else None,
            }
            for c in contribs
            if c.contribution_type == "human"
        ]

    # Fallback: primary creator from asset record
    if asset.creator_name:
        return [{
            "contributor_name": asset.creator_name,
            "role": "primary creator",
            "contribution_type": "human",
            "creative_contribution_pct": None,
            "ownership_split_pct": 100.0,
            "ai_assisted_pct": None,
            "wallet_address": None,
            "added_at": (
                asset.created_at.isoformat() if asset.created_at else None
            ),
        }]

    return []


def _build_ai_tools_section(asset) -> dict:
    """AI tools declared in provenance and detected by the AI detection service."""
    declared: list = []
    if asset.ai_tools_used_json:
        try:
            declared = json.loads(asset.ai_tools_used_json)
        except (json.JSONDecodeError, TypeError):
            declared = []

    return {
        "declared_tools": declared,
        "disclosure_complete": asset.ai_disclosure_complete,
        "ai_modification_by_human": asset.ai_modification_by_human,
        "ai_detection_score": asset.ai_detection_score,
        "ai_detection_pct": (
            round(asset.ai_detection_score * 100, 1)
            if asset.ai_detection_score is not None else None
        ),
        "ai_disclosure_status": asset.ai_disclosure,   # "human" | "ai" | "mixed" | None
        "disclosure_note": _disclosure_note(asset),
    }


def _build_workflow_lineage(events: list) -> list:
    """
    Ordered list of every provenance event — the full audit trail of actions
    performed on this asset from ingest to present.
    """
    return [
        {
            "step": i + 1,
            "event_type": ev.event_type,
            "description": ev.description,
            "tool_used": ev.tool_used,
            "actor": ev.actor_name,
            "performed_by": ev.human_or_ai,
            "timestamp": ev.timestamp.isoformat() if ev.timestamp else None,
            "event_hash": ev.event_hash,
        }
        for i, ev in enumerate(events)
    ]


def _build_transformation_chain(asset, events: list) -> list:
    """
    Subset of the workflow focused on transformation steps — both declared by
    the creator and detected via provenance events.
    """
    chain = []

    # Declared transformation from provenance fields
    declared_forms = [
        ("creative_direction", asset.human_creative_direction,  "Human creative direction established"),
        ("editing",            asset.human_editing_present,     "Human editing applied"),
        ("arrangement",        asset.human_arrangement_present, "Human arrangement applied"),
        ("lyrics",             asset.human_lyrics_present,      "Human lyrics added"),
        ("performance",        asset.human_performance_present, "Human performance recorded"),
        ("transformation",     asset.human_transformation_present, "Human transformation applied"),
    ]
    for form_type, present, label in declared_forms:
        if present is True:
            chain.append({
                "step_type": "declared_human",
                "form": form_type,
                "label": label,
                "source": "creator_declaration",
            })

    # Watermark = system transformation
    wm_events = [ev for ev in events if ev.event_type == "watermark"]
    for ev in wm_events:
        chain.append({
            "step_type": "system_transformation",
            "form": "watermark",
            "label": ev.description or "Watermark applied",
            "tool": ev.tool_used,
            "timestamp": ev.timestamp.isoformat() if ev.timestamp else None,
            "source": "provenance_event",
        })

    # Human modification of AI output
    if asset.ai_modification_by_human is True:
        chain.append({
            "step_type": "declared_human",
            "form": "ai_modification",
            "label": "Human modification of AI-generated content",
            "source": "creator_declaration",
        })

    return chain


def _build_timestamps(asset, events: list, certs: list) -> dict:
    """Key timestamps in the asset's lifecycle."""
    upload_ev = next((ev for ev in events if ev.event_type == "upload"), None)
    cert_ev   = next((ev for ev in events if ev.event_type == "certificate_issued"), None)

    return {
        "asset_created_at": (
            asset.created_at.isoformat() if asset.created_at else None
        ),
        "first_upload_event": (
            upload_ev.timestamp.isoformat() if upload_ev and upload_ev.timestamp else None
        ),
        "first_certificate_issued": (
            certs[0].issued_at.isoformat() if certs and certs[0].issued_at else None
        ),
        "latest_certificate_issued": (
            certs[-1].issued_at.isoformat() if certs and certs[-1].issued_at else None
        ),
        "first_certificate_event": (
            cert_ev.timestamp.isoformat() if cert_ev and cert_ev.timestamp else None
        ),
        "total_provenance_events": len(events),
        "total_certificates_issued": len(certs),
        "event_timeline": [
            {
                "event_type": ev.event_type,
                "timestamp": ev.timestamp.isoformat() if ev.timestamp else None,
            }
            for ev in events
        ],
    }


def _build_contributor_declarations(asset, contribs: list) -> list:
    """
    Formal authorship declarations — one per contributor, or one for the
    primary creator if no Contributor rows exist.
    """
    if contribs:
        return [
            {
                "declarant": c.contributor_name,
                "role": c.role,
                "declares": (
                    f"{c.contributor_name} declares their role as {c.role or 'contributor'} "
                    f"on this work, with a creative contribution of "
                    f"{c.creative_contribution_pct or 'undeclared'}%."
                ),
                "ai_assisted_pct": c.ai_assisted_pct,
            }
            for c in contribs
        ]

    if asset.creator_name:
        summary = asset.human_authorship_summary or ""
        return [{
            "declarant": asset.creator_name,
            "role": "primary creator",
            "declares": (
                f"{asset.creator_name} declares sole authorship of this work. "
                + (summary if summary else "")
            ).strip(),
            "ai_assisted_pct": None,
        }]

    return []


def _build_ownership_declarations(asset, contribs: list, certs: list) -> dict:
    """
    Legal ownership declarations — separate from creative contribution.
    """
    certificate_class = None
    if certs:
        # The latest certificate holds the most current class
        try:
            latest_cert_data = json.loads(certs[-1].cert_json or "{}")
            certificate_class = latest_cert_data.get("certificate_class")
        except (json.JSONDecodeError, TypeError):
            certificate_class = certs[-1].certificate_class

    ownership_rows = []
    if contribs:
        for c in contribs:
            ownership_rows.append({
                "owner_name": c.contributor_name,
                "role": c.role,
                "ownership_split_pct": (
                    c.ownership_split_pct or c.split_percentage
                ),
                "creative_contribution_pct": c.creative_contribution_pct,
                "ai_assisted_pct": c.ai_assisted_pct,
            })
    else:
        ownership_rows.append({
            "owner_name": asset.copyright_owner or asset.creator_name or "Unknown",
            "role": "copyright owner",
            "ownership_split_pct": 100.0,
            "creative_contribution_pct": None,
            "ai_assisted_pct": None,
        })

    return {
        "copyright_owner": asset.copyright_owner or asset.creator_name or "Unknown",
        "license_type": asset.license_type,
        "certificate_class": certificate_class,
        "certificate_class_note": (
            "Ownership splits are legal declarations and do not alter "
            "creative contribution percentages documented in Section A."
        ),
        "ownership_splits": ownership_rows,
        "certificate_ids": [c.cert_id for c in certs],
    }


def _build_readiness_section(asset) -> dict:
    """Copyright readiness score and label as stored at ingest time."""
    human_authorship_evidence = {
        "creative_direction": asset.human_creative_direction,
        "editing": asset.human_editing_present,
        "arrangement": asset.human_arrangement_present,
        "lyrics": asset.human_lyrics_present,
        "performance": asset.human_performance_present,
        "transformation": asset.human_transformation_present,
        "summary": asset.human_authorship_summary,
    }
    confirmed_count = sum(
        1 for v in human_authorship_evidence.values()
        if v is True
    )

    return {
        "score": asset.copyright_readiness_score,
        "label": asset.copyright_readiness_label,
        "human_authorship_evidence": human_authorship_evidence,
        "confirmed_human_authorship_forms": confirmed_count,
        "ai_disclosure_complete": asset.ai_disclosure_complete,
        "ai_modification_by_human": asset.ai_modification_by_human,
        "authorship_summary": asset.human_authorship_summary,
        "trust_score": asset.trust_score,
        "trust_label": asset.content_label,
        "scoring_note": (
            "copyright_readiness_score measures the strength of documented human "
            "authorship evidence only. It is separate from trust_score, which "
            "measures provenance integrity."
        ),
    }


def _compute_provenance_continuity(asset, events: list, certs: list) -> dict:
    """
    Provenance continuity score — measures completeness of the provenance chain.
    Separate from both trust_score and copyright_readiness_score.
    """
    score = 0.0
    factors = []
    gaps = []

    event_types = {ev.event_type for ev in events}

    if "upload" in event_types:
        score += _CONTINUITY_WEIGHTS["upload_event"]
        factors.append("Upload event present in provenance chain")
    else:
        gaps.append("No upload event found in provenance chain")

    if "certificate_issued" in event_types or certs:
        score += _CONTINUITY_WEIGHTS["certificate_event"]
        factors.append(f"Certificate issued ({len(certs)} on record)")
    else:
        gaps.append("No certificate event found in provenance chain")

    has_all_hashes = bool(asset.sha256 and asset.blake3 and asset.phash)
    if has_all_hashes:
        score += _CONTINUITY_WEIGHTS["all_hashes"]
        factors.append("SHA-256, BLAKE3, and perceptual hash all present")
    elif asset.sha256 and asset.blake3:
        score += _CONTINUITY_WEIGHTS["all_hashes"] * 0.7
        factors.append("SHA-256 and BLAKE3 present (no perceptual hash)")
        gaps.append("Perceptual hash absent")
    else:
        gaps.append("One or more cryptographic hashes absent")

    if "watermark" in event_types:
        score += _CONTINUITY_WEIGHTS["watermark_event"]
        factors.append("Watermark event recorded in provenance chain")

    if asset.manifest_path:
        score += _CONTINUITY_WEIGHTS["manifest_present"]
        factors.append("Provenance manifest on record")
    else:
        gaps.append("No provenance manifest path recorded")

    has_ownership = bool(asset.copyright_owner or asset.creator_name)
    if has_ownership:
        score += _CONTINUITY_WEIGHTS["ownership_declared"]
        factors.append("Ownership / creator identity declared")
    else:
        gaps.append("No ownership or creator name declared")

    # Event integrity: all events have a non-empty event_hash
    events_with_hash = [ev for ev in events if ev.event_hash]
    if events and len(events_with_hash) == len(events):
        score += _CONTINUITY_WEIGHTS["event_integrity"]
        factors.append(f"All {len(events)} provenance events carry integrity hashes")
    elif events:
        ratio = len(events_with_hash) / len(events)
        score += _CONTINUITY_WEIGHTS["event_integrity"] * ratio
        gaps.append(
            f"{len(events) - len(events_with_hash)} event(s) missing integrity hash"
        )

    # Chain continuity: timestamps must be non-decreasing
    timestamps = [ev.timestamp for ev in events if ev.timestamp]
    chain_ok = all(timestamps[i] <= timestamps[i + 1] for i in range(len(timestamps) - 1))
    if chain_ok and timestamps:
        score += _CONTINUITY_WEIGHTS["chain_continuous"]
        factors.append("Provenance event timestamps are chronologically ordered")
    elif timestamps:
        gaps.append("Provenance event timestamps contain out-of-order entries")

    score = round(min(1.0, score), 4)

    return {
        "score": score,
        "label": _continuity_label(score),
        "factors": factors,
        "gaps": gaps,
        "total_events": len(events),
        "total_certificates": len(certs),
        "scoring_note": (
            "Provenance continuity score measures completeness of the documented "
            "provenance chain — separate from trust_score and copyright_readiness_score."
        ),
    }


# ── Helpers ────────────────────────────────────────────────────────────────────

def _continuity_label(score: float) -> str:
    if score >= 0.80:
        return "complete"
    if score >= 0.55:
        return "partial"
    if score >= 0.30:
        return "minimal"
    return "insufficient"


def _disclosure_note(asset) -> str:
    ai_score = asset.ai_detection_score or 0.0
    disclosed = asset.ai_disclosure_complete or (asset.ai_disclosure in ("ai", "mixed"))
    if ai_score >= 0.85 and not disclosed:
        return "AI generation strongly detected but not fully disclosed."
    if ai_score >= 0.40 and not disclosed:
        return "AI involvement detected; disclosure may be incomplete."
    if ai_score >= 0.40 and disclosed:
        return "AI involvement detected and disclosed."
    if disclosed:
        return "AI disclosure submitted; no significant AI involvement detected."
    return "No significant AI involvement detected."
