"""OmniSpectra V1 — multi-signal forensic evidence orchestration.

OmniSpectra does not pretend any single detector can prove authenticity. It
normalizes independent evidence sources (metadata anomalies, synthetic-media
probability, C2PA Content Credentials, watermark state, and HumanProof chain
integrity) into one explainable report while preserving the original signals.

The V1 verdict is intentionally rule-based and conservative. It is a review
priority, not a legal/authorship determination and not a replacement for the
existing Omni Veil Trust Score.
"""
from __future__ import annotations

from typing import Any, Optional


ENGINE_NAME = "Omni Veil OmniSpectra"
ENGINE_VERSION = "1.0.1"


def _synthetic_signal(
    score: Optional[float],
    *,
    provider: Optional[str] = None,
    model: Optional[str] = None,
) -> dict:
    if score is None:
        return {
            "available": False,
            "probability": None,
            "risk": "unknown",
            "provider": provider,
            "model": model,
            "note": "No synthetic-media detector result is available for this asset.",
        }

    probability = max(0.0, min(1.0, float(score)))
    if probability >= 0.80:
        risk = "high"
    elif probability >= 0.50:
        risk = "elevated"
    else:
        risk = "low"

    return {
        "available": True,
        "probability": round(probability, 4),
        "probability_pct": round(probability * 100, 2),
        "risk": risk,
        "provider": provider,
        "model": model,
        "note": (
            "Model probability is one forensic signal. It does not independently prove "
            "that an asset is human-made or AI-generated."
        ),
    }


def _metadata_signal(anomaly: Optional[dict]) -> dict:
    if not anomaly:
        return {
            "available": False,
            "anomaly_score": None,
            "risk": "unknown",
            "flags": [],
            "summary": "Metadata anomaly analysis is unavailable.",
        }

    score = int(anomaly.get("anomaly_score") or 0)
    flags = anomaly.get("flags") if isinstance(anomaly.get("flags"), list) else []
    if score >= 60:
        risk = "high"
    elif score >= 30:
        risk = "elevated"
    else:
        risk = "low"

    return {
        "available": True,
        "anomaly_score": max(0, min(100, score)),
        "risk": risk,
        "flags": flags,
        "summary": anomaly.get("anomaly_summary") or "Metadata anomaly analysis complete.",
        "engine_version": anomaly.get("engine_version"),
    }


def _c2pa_signal(c2pa: Optional[dict]) -> dict:
    if not c2pa:
        return {
            "available": False,
            "manifest_present": None,
            "validation_state": "unknown",
            "risk": "unknown",
        }

    state = str(c2pa.get("validation_state") or "unknown")
    present = c2pa.get("manifest_present")

    if state == "invalid":
        risk = "high"
    elif state in {"read_error", "sdk_unavailable"}:
        risk = "unknown"
    elif present is False:
        # No Content Credentials is not itself suspicious; many legitimate files
        # have no C2PA manifest.
        risk = "neutral"
    else:
        risk = "low"

    return {
        "available": state not in {"sdk_unavailable", "read_error", "unknown"},
        "manifest_present": present,
        "validation_state": state,
        "risk": risk,
        "claim_generator": c2pa.get("claim_generator"),
        "active_manifest": c2pa.get("active_manifest"),
        "actions": c2pa.get("actions") if isinstance(c2pa.get("actions"), list) else [],
        "validation_error_count": int(c2pa.get("validation_error_count") or 0),
        "evidence_note": c2pa.get("evidence_note"),
    }


def _watermark_signal(*, applied: Optional[bool], visible: Optional[bool], invisible: Optional[bool]) -> dict:
    return {
        "available": any(value is not None for value in (applied, visible, invisible)),
        "applied": bool(applied),
        "visible": bool(visible),
        "invisible": bool(invisible),
        "risk": "low" if bool(applied) else "neutral",
        "note": "Watermark presence supports continuity but absence is not proof of manipulation.",
    }


def _humanproof_signal(humanproof: Optional[dict]) -> dict:
    if not humanproof:
        return {
            "available": False,
            "status": None,
            "chain_valid": None,
            "risk": "neutral",
        }

    chain = humanproof.get("chain_integrity") if isinstance(humanproof.get("chain_integrity"), dict) else {}
    chain_valid = chain.get("valid")
    status = humanproof.get("status")

    if chain_valid is False or status == "integrity_failed":
        risk = "high"
    elif status == "complete" and chain_valid is True:
        risk = "low"
    else:
        risk = "elevated"

    return {
        "available": True,
        "status": status,
        "chain_valid": chain_valid,
        "event_count": chain.get("event_count") or humanproof.get("event_count"),
        "asset_bound": humanproof.get("asset_bound"),
        "ai_disclosure": humanproof.get("ai_disclosure"),
        "risk": risk,
    }


def _verdict(signals: dict) -> tuple[str, list[str]]:
    reasons: list[str] = []

    metadata = signals["metadata_anomalies"]
    synthetic = signals["synthetic_detection"]
    c2pa = signals["content_credentials"]
    humanproof = signals["humanproof"]

    if c2pa.get("risk") == "high":
        reasons.append("C2PA validation reported a failure.")
    if humanproof.get("risk") == "high":
        reasons.append("HumanProof chain integrity failed or is invalid.")
    if metadata.get("risk") == "high":
        reasons.append("Metadata anomaly score is high.")
    if synthetic.get("risk") == "high":
        reasons.append("Synthetic-media detector probability is high.")

    if reasons:
        return "high_review_priority", reasons

    elevated: list[str] = []
    if metadata.get("risk") == "elevated":
        elevated.append("Metadata anomalies warrant review.")
    if synthetic.get("risk") == "elevated":
        elevated.append("Synthetic-media detector probability is elevated.")
    if humanproof.get("risk") == "elevated":
        elevated.append("HumanProof evidence is incomplete.")

    if elevated:
        return "review_recommended", elevated

    available_count = sum(
        1
        for key in ("metadata_anomalies", "synthetic_detection", "content_credentials", "humanproof")
        if signals[key].get("available")
    )
    if available_count == 0:
        return "insufficient_evidence", ["No substantive forensic evidence sources are available."]

    return "no_major_flags", ["No high-priority forensic conflicts were found in the available evidence."]


def build_omnispectra_report(
    *,
    omni_id: Optional[str] = None,
    filename: Optional[str] = None,
    sha256: Optional[str] = None,
    ai_detection_score: Optional[float] = None,
    detector_provider: Optional[str] = None,
    detector_model: Optional[str] = None,
    anomaly: Optional[dict] = None,
    c2pa: Optional[dict] = None,
    watermark_applied: Optional[bool] = None,
    watermark_visible: Optional[bool] = None,
    watermark_invisible: Optional[bool] = None,
    humanproof: Optional[dict] = None,
) -> dict:
    signals = {
        "metadata_anomalies": _metadata_signal(anomaly),
        "synthetic_detection": _synthetic_signal(
            ai_detection_score,
            provider=detector_provider,
            model=detector_model,
        ),
        "content_credentials": _c2pa_signal(c2pa),
        "watermark": _watermark_signal(
            applied=watermark_applied,
            visible=watermark_visible,
            invisible=watermark_invisible,
        ),
        "humanproof": _humanproof_signal(humanproof),
    }
    verdict, reasons = _verdict(signals)

    return {
        "engine": ENGINE_NAME,
        "engine_version": ENGINE_VERSION,
        "omni_id": omni_id,
        "filename": filename,
        "sha256": sha256,
        "verdict": verdict,
        "reasons": reasons,
        "signals": signals,
        "limitations": [
            "OmniSpectra is an evidence orchestration layer, not a single-model authenticity oracle.",
            "Detector probabilities can be wrong and must be interpreted with provenance and contextual evidence.",
            "C2PA absence is neutral; C2PA presence validates signed provenance bindings, not every factual assertion.",
            "This report is not a legal determination of authorship, copyright ownership, or fraud.",
        ],
    }
