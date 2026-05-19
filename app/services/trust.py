from dataclasses import dataclass
from typing import Optional

@dataclass
class TrustSignals:
    has_sha256: Optional[bool] = True
    has_blake3: Optional[bool] = None
    has_phash: Optional[bool] = None
    invisible_wm_verified: Optional[bool] = None
    invisible_wm_confidence: Optional[float] = None
    phash_collision: Optional[bool] = None
    has_exif: Optional[bool] = None
    has_gps: Optional[bool] = None
    exif_software: Optional[str] = None
    has_creator_name: Optional[bool] = None
    has_creator_org: Optional[bool] = None
    has_copyright: Optional[bool] = None
    has_license_url: Optional[bool] = None
    is_ai_generated: Optional[bool] = None
    is_ai_disclosed: Optional[bool] = None
    ai_detection_score: Optional[float] = None
    transformation_level: Optional[str] = None
    human_contribution_count: Optional[int] = None
    has_daw: Optional[bool] = None

@dataclass
class TrustResult:
    score: float
    label: str
    reasons: list
    signals_used: list

def compute_trust_score(signals: TrustSignals) -> TrustResult:
    score = 0.50
    reasons = []
    used = []
    if signals.has_blake3:
        score += 0.05
        reasons.append("BLAKE3 cryptographic hash verified")
        used.append("has_blake3")
    if signals.invisible_wm_verified is True:
        conf = signals.invisible_wm_confidence or 1.0
        score += 0.10
        reasons.append(f"Invisible watermark verified ({int(conf*100)}% confidence)")
        used.append("invisible_wm_verified")
    elif signals.invisible_wm_verified is False:
        score -= 0.30
        reasons.append("Invisible watermark FAILED")
        used.append("invisible_wm_verified")
    if signals.has_phash:
        score += 0.03
        reasons.append("Perceptual fingerprint generated")
        used.append("has_phash")
    if signals.has_exif is True:
        score += 0.08
        reasons.append("Authentic EXIF metadata present")
        used.append("has_exif")
    elif signals.has_exif is False:
        score -= 0.03
        reasons.append("No EXIF metadata detected")
        used.append("has_exif")
    if signals.has_gps is True:
        score += 0.06
        reasons.append("GPS location data present")
        used.append("has_gps")
    if signals.has_creator_name is True:
        score += 0.06
        reasons.append("Creator name registered")
        used.append("has_creator_name")
    if signals.has_creator_org is True:
        score += 0.05
        reasons.append("Creator organisation registered")
        used.append("has_creator_org")
    if signals.has_copyright is True:
        score += 0.05
        reasons.append("Copyright notice registered")
        used.append("has_copyright")
    if signals.has_license_url is True:
        score += 0.04
        reasons.append("License URL provided")
        used.append("has_license_url")
    ai = signals.ai_detection_score
    if ai is not None:
        used.append("ai_detection_score")
        if ai >= 0.90:
            score -= 0.25
            reasons.append(f"AI generation detected high confidence ({int(ai*100)}%)")
        elif ai >= 0.70:
            score -= 0.15
            reasons.append(f"AI generation likely ({int(ai*100)}%)")
        elif ai >= 0.40:
            score -= 0.05
            reasons.append(f"Possible AI involvement ({int(ai*100)}%)")
        elif ai < 0.20:
            score += 0.05
            reasons.append(f"Likely human-created, AI score low ({int(ai*100)}%)")
    if signals.is_ai_generated is True:
        score -= 0.05
        reasons.append("Creator disclosed AI-generated content")
        used.append("is_ai_generated")
    if signals.transformation_level:
        level = signals.transformation_level.lower()
        if level == "substantial":
            score += 0.12
            reasons.append("Substantial human creative transformation declared")
        elif level == "moderate":
            score += 0.07
            reasons.append("Moderate human transformation declared")
        elif level == "minor":
            score += 0.03
            reasons.append("Minor human transformation declared")
        used.append("transformation_level")
    if signals.human_contribution_count:
        bonus = min(signals.human_contribution_count * 0.03, 0.10)
        score += bonus
        reasons.append(f"{signals.human_contribution_count} human contribution signals")
        used.append("human_contribution_count")
    if signals.has_daw is True:
        score += 0.04
        reasons.append("DAW software declared")
        used.append("has_daw")
    score = round(max(0.0, min(1.0, score)), 4)
    label = _assign_label(score, signals)
    return TrustResult(score=score, label=label, reasons=reasons, signals_used=used)

def _assign_label(score, signals):
    if signals.invisible_wm_verified is False or signals.phash_collision is True:
        return "tampered"
    ai = signals.ai_detection_score or 0.0
    if ai >= 0.85:
        return "synthetic" if not signals.is_ai_generated else "ai_assisted"
    if ai >= 0.40 or signals.is_ai_generated is True:
        return "ai_assisted"
    if score >= 0.65:
        return "human_verified"
    if score >= 0.45:
        return "unverified"
    return "unverified"
