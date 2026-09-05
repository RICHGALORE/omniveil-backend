"""Copyright Readiness Report Generator — Omni Veil Authorship Support Infrastructure.

Reports persisted evidence without inventing ownership, sole authorship,
percentages, AI status, names, or counts. Creator attribution remains separate
from contributor attribution and rights declarations.
"""

import json
import uuid
from datetime import datetime, timezone

from app.services.asset_facts import (
    ai_facts,
    asset_identity,
    contributor_facts,
    human_authorship,
    ownership_facts,
    percentage,
    readiness_facts,
    trust_facts,
)
from app.services.copyright_readiness import LEGAL_DISCLAIMER

_CONTINUITY_WEIGHTS = {
    "upload_event": 0.20,
    "certificate_event": 0.20,
    "all_hashes": 0.15,
    "watermark_event": 0.10,
    "manifest_present": 0.10,
    "ownership_declared": 0.10,
    "event_integrity": 0.10,
    "chain_continuous": 0.05,
}


def generate_copyright_readiness_report(asset) -> dict:
    now = datetime.now(timezone.utc).isoformat()
    events = sorted(asset.provenance_events, key=lambda e: e.timestamp)
    certs = sorted(asset.certificates, key=lambda c: c.issued_at)
    contribs = list(asset.contributors)
    facts = {
        "identity": asset_identity(asset),
        "trust": trust_facts(asset),
        "ai": ai_facts(asset),
        "rights": ownership_facts(asset, contribs),
        "copyright_readiness": readiness_facts(asset),
    }

    return {
        "report_id": str(uuid.uuid4()),
        "report_type": "copyright_readiness_report",
        "report_version": "1.1",
        "omni_id": asset.omni_id,
        "generated_at": now,
        "stored_facts": facts,
        "human_contributors": _build_contributors_section(contribs),
        "ai_tools": _build_ai_tools_section(asset),
        "workflow_lineage": _build_workflow_lineage(events),
        "transformation_chain": _build_transformation_chain(asset, events),
        "timestamps": _build_timestamps(asset, events, certs),
        "contributor_declarations": _build_contributor_declarations(contribs),
        "ownership_declarations": _build_ownership_declarations(asset, contribs, certs),
        "copyright_readiness": _build_readiness_section(asset),
        "provenance_continuity": _compute_provenance_continuity(asset, events, certs, contribs),
        "legal_disclaimer": LEGAL_DISCLAIMER,
    }


def _build_contributors_section(contribs: list) -> list:
    """Return persisted human contributor rows only; never infer from creator."""
    return [
        {
            "contributor_name": item["name"],
            "role": item["role"],
            "contribution_type": item["contribution_type"],
            "creative_contribution_pct": item["creative_contribution_pct"],
            "ownership_split_pct": item["ownership_split_pct"],
            "ai_assisted_pct": item["ai_assisted_pct"],
            "added_at": item["added_at"],
        }
        for item in contributor_facts(contribs)
        if item["contribution_type"] == "human"
    ]


def _build_ai_tools_section(asset) -> dict:
    facts = ai_facts(asset)
    return {
        "declared_tools": facts["declared_tools"],
        "disclosure_complete": facts["disclosure_complete"],
        "ai_modification_by_human": facts["modification_by_human"],
        "ai_detection_score": facts["detection_score"],
        "ai_detection_pct": facts["detection_pct"],
        "ai_disclosure_status": facts["disclosure"],
        "disclosure_note": _disclosure_note(asset),
    }


def _build_workflow_lineage(events: list) -> list:
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
    chain = []
    declared_forms = [
        ("creative_direction", asset.human_creative_direction, "Human creative direction established"),
        ("editing", asset.human_editing_present, "Human editing applied"),
        ("arrangement", asset.human_arrangement_present, "Human arrangement applied"),
        ("lyrics", asset.human_lyrics_present, "Human lyrics added"),
        ("performance", asset.human_performance_present, "Human performance recorded"),
        ("transformation", asset.human_transformation_present, "Human transformation applied"),
    ]
    for form_type, present, label in declared_forms:
        if present is True:
            chain.append({
                "step_type": "declared_human",
                "form": form_type,
                "label": label,
                "source": "creator_declaration",
            })

    for ev in [event for event in events if event.event_type == "watermark"]:
        chain.append({
            "step_type": "system_transformation",
            "form": "watermark",
            "label": ev.description or "Watermark applied",
            "tool": ev.tool_used,
            "timestamp": ev.timestamp.isoformat() if ev.timestamp else None,
            "source": "provenance_event",
        })

    if asset.ai_modification_by_human is True:
        chain.append({
            "step_type": "declared_human",
            "form": "ai_modification",
            "label": "Human modification of AI output documented",
            "source": "creator_declaration",
        })
    return chain


def _build_timestamps(asset, events: list, certs: list) -> dict:
    upload_ev = next((ev for ev in events if ev.event_type == "upload"), None)
    cert_ev = next((ev for ev in events if ev.event_type == "certificate_issued"), None)
    return {
        "asset_created_at": asset.created_at.isoformat() if asset.created_at else None,
        "first_upload_event": upload_ev.timestamp.isoformat() if upload_ev and upload_ev.timestamp else None,
        "first_certificate_issued": certs[0].issued_at.isoformat() if certs and certs[0].issued_at else None,
        "latest_certificate_issued": certs[-1].issued_at.isoformat() if certs and certs[-1].issued_at else None,
        "first_certificate_event": cert_ev.timestamp.isoformat() if cert_ev and cert_ev.timestamp else None,
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


def _build_contributor_declarations(contribs: list) -> list:
    """Only persisted contributor records become contributor declarations."""
    declarations = []
    for item in contributor_facts(contribs):
        creative = item["creative_contribution_pct"]
        creative_text = f"{creative}%" if creative is not None else "undeclared"
        declarations.append({
            "declarant": item["name"],
            "role": item["role"],
            "declares": (
                f"Stored contributor record: {item['name']} — role "
                f"{item['role'] or 'undeclared'}, creative contribution {creative_text}."
            ),
            "ai_assisted_pct": item["ai_assisted_pct"],
        })
    return declarations


def _build_ownership_declarations(asset, contribs: list, certs: list) -> dict:
    certificate_class = None
    if certs:
        try:
            latest_cert_data = json.loads(certs[-1].cert_json or "{}")
            certificate_class = latest_cert_data.get("certificate_class")
        except (json.JSONDecodeError, TypeError):
            certificate_class = certs[-1].certificate_class

    rights = ownership_facts(asset, contribs)
    return {
        "copyright_owner": rights["copyright_owner"],
        "license_type": rights["license_type"],
        "certificate_class": certificate_class,
        "certificate_class_note": (
            "Ownership information is reported only from explicit stored declarations; "
            "creator attribution does not imply ownership."
        ),
        "ownership_splits": rights["ownership_splits"],
        "ownership_total_pct": rights["ownership_total_pct"],
        "ownership_declared": rights["ownership_declared"],
        "certificate_ids": [c.cert_id for c in certs],
    }


def _build_readiness_section(asset) -> dict:
    readiness = readiness_facts(asset)
    evidence = human_authorship(asset)
    return {
        "score": readiness["score"],
        "label": readiness["label"],
        "certificate_class": readiness["certificate_class"],
        "certificate_class_label": readiness["certificate_class_label"],
        "human_authorship_evidence": evidence,
        "confirmed_human_authorship_forms": readiness["confirmed_human_authorship_forms"],
        "ai_disclosure_complete": asset.ai_disclosure_complete,
        "ai_modification_by_human": asset.ai_modification_by_human,
        "authorship_summary": asset.human_authorship_summary,
        "trust_score": asset.trust_score,
        "trust_label": asset.content_label,
        "scoring_note": (
            "copyright_readiness_score measures documented human-authorship evidence only. "
            "It is separate from trust_score and is not a legal ownership determination."
        ),
    }


def _compute_provenance_continuity(asset, events: list, certs: list, contribs: list) -> dict:
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

    rights = ownership_facts(asset, contribs)
    if rights["ownership_declared"]:
        score += _CONTINUITY_WEIGHTS["ownership_declared"]
        factors.append("Explicit ownership declaration present")
    else:
        gaps.append("No explicit ownership declaration recorded")

    events_with_hash = [ev for ev in events if ev.event_hash]
    if events and len(events_with_hash) == len(events):
        score += _CONTINUITY_WEIGHTS["event_integrity"]
        factors.append(f"All {len(events)} provenance events carry integrity hashes")
    elif events:
        ratio = len(events_with_hash) / len(events)
        score += _CONTINUITY_WEIGHTS["event_integrity"] * ratio
        gaps.append(f"{len(events) - len(events_with_hash)} event(s) missing integrity hash")

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
            "Provenance continuity measures completeness of the documented chain; "
            "it is separate from trust_score and copyright_readiness_score."
        ),
    }


def _continuity_label(score: float) -> str:
    if score >= 0.80:
        return "complete"
    if score >= 0.55:
        return "partial"
    if score >= 0.30:
        return "minimal"
    return "insufficient"


def _disclosure_note(asset) -> str:
    facts = ai_facts(asset)
    disclosure = facts["disclosure"]
    score = facts["detection_score"]

    if score is None:
        if disclosure == "ai_generated":
            return "Creator declared AI-generated content; detector result is not available."
        if disclosure == "ai_assisted":
            return "Creator declared AI-assisted content; detector result is not available."
        if disclosure == "human":
            return "Creator declared human-created content; detector result is not available."
        if disclosure == "unknown":
            return "Creator marked AI status unknown; detector result is not available."
        return "No creator AI-status declaration or detector result is available."

    if score >= 0.85 and disclosure not in {"ai_generated", "ai_assisted"}:
        return "High synthetic-media probability is present without a matching AI-use declaration."
    if score >= 0.40 and disclosure not in {"ai_generated", "ai_assisted"}:
        return "Synthetic-media probability indicates possible AI involvement; disclosure may be incomplete."
    if score >= 0.40 and disclosure in {"ai_generated", "ai_assisted"}:
        return "AI involvement is both declared and supported by a detector signal."
    if disclosure in {"ai_generated", "ai_assisted"}:
        return "AI use is declared; the available detector score is below the review threshold."
    if disclosure == "human":
        return "Human-created status is declared; detector probability is reported separately and is not proof of authorship."
    return "Detector probability is reported as a forensic signal, not a determination."
