"""
Copyright Readiness System — authorship support infrastructure for Omni Veil.

Computes a copyright_readiness_score based on documented human authorship evidence.
This score is entirely separate from trust_score (which measures provenance integrity).

IMPORTANT: Omni Veil provides provenance and authorship documentation infrastructure.
Final copyright determinations are made by the applicable copyright authority.
"""

from dataclasses import dataclass, field
from typing import Optional, List

LEGAL_DISCLAIMER = (
    "Omni Veil provides provenance and authorship documentation infrastructure. "
    "Final copyright determinations are made by the applicable copyright authority."
)

_LABEL_STRONG = 0.75
_LABEL_MODERATE = 0.50
_LABEL_LIMITED = 0.25


@dataclass
class AuthorshipSignals:
    """Known authorship/disclosure inputs. None means not assessed."""
    human_creative_direction: Optional[bool] = None
    human_editing_present: Optional[bool] = None
    human_arrangement_present: Optional[bool] = None
    human_lyrics_present: Optional[bool] = None
    human_performance_present: Optional[bool] = None
    human_transformation_present: Optional[bool] = None

    # Form completion is not the same thing as admitting AI use.
    ai_disclosure_complete: Optional[bool] = None
    ai_tools_used: Optional[List[str]] = field(default_factory=list)
    ai_modification_by_human: Optional[bool] = None

    ai_detection_score: Optional[float] = None
    is_ai_disclosed: Optional[bool] = None  # True only when AI use itself was declared

    human_contributor_count: Optional[int] = None


@dataclass
class CopyrightReadinessResult:
    score: float
    label: str
    certificate_class: str
    factors_supporting: List[str]
    factors_limiting: List[str]
    legal_disclaimer: str = LEGAL_DISCLAIMER


_HUMAN_FIELD_WEIGHT = 0.12
_HONEST_AI_DISCLOSURE_BONUS = 0.08
_COMPLETED_DISCLOSURE_FORM_BONUS = 0.05
_HUMAN_MODIFIED_AI_BONUS = 0.08
_UNDISCLOSED_AI_PENALTY = -0.20
_NO_HUMAN_FIELDS_PENALTY = -0.10
_FULLY_AI_NO_HUMAN_PENALTY = -0.20
_PER_CONTRIBUTOR_BONUS = 0.03

_AI_DETECTED_THRESHOLD = 0.40
_AI_HIGH_CONFIDENCE = 0.85
_CONTRIBUTOR_BONUS_CAP = 0.09


def compute_copyright_readiness(signals: AuthorshipSignals) -> CopyrightReadinessResult:
    """Measure documented authorship evidence, not legal copyright status."""
    score = 0.0
    supporting: List[str] = []
    limiting: List[str] = []

    human_field_map = [
        (signals.human_creative_direction, "Human creative direction documented"),
        (signals.human_editing_present, "Human editing documented"),
        (signals.human_arrangement_present, "Human arrangement documented"),
        (signals.human_lyrics_present, "Human lyrics documented"),
        (signals.human_performance_present, "Human performance documented"),
        (signals.human_transformation_present, "Human transformation documented"),
    ]

    confirmed_human_fields = sum(1 for val, _ in human_field_map if val is True)
    for val, label in human_field_map:
        if val is True:
            score += _HUMAN_FIELD_WEIGHT
            supporting.append(label)

    if confirmed_human_fields == 0:
        score += _NO_HUMAN_FIELDS_PENALTY
        limiting.append("No human authorship fields documented")

    ai_detected = (signals.ai_detection_score or 0.0) >= _AI_DETECTED_THRESHOLD
    ai_use_disclosed = signals.is_ai_disclosed is True
    disclosure_form_complete = signals.ai_disclosure_complete is True
    ai_tools_present = bool(signals.ai_tools_used)

    if ai_detected and ai_use_disclosed:
        score += _HONEST_AI_DISCLOSURE_BONUS
        supporting.append("AI use detected and explicitly disclosed")
    elif ai_detected and not ai_use_disclosed:
        score += _UNDISCLOSED_AI_PENALTY
        limiting.append(
            "AI detector signal present without an explicit AI-use declaration"
        )
    elif not ai_detected and disclosure_form_complete:
        score += _COMPLETED_DISCLOSURE_FORM_BONUS
        supporting.append("AI disclosure form completed")

    if signals.ai_modification_by_human is True:
        score += _HUMAN_MODIFIED_AI_BONUS
        supporting.append("Human modification of AI output documented")

    fully_ai = (signals.ai_detection_score or 0.0) >= _AI_HIGH_CONFIDENCE
    if (
        fully_ai
        and confirmed_human_fields == 0
        and signals.ai_modification_by_human is not True
    ):
        score += _FULLY_AI_NO_HUMAN_PENALTY
        limiting.append(
            "High synthetic-media probability with no documented human authorship or modification"
        )

    if signals.human_contributor_count:
        bonus = min(
            signals.human_contributor_count * _PER_CONTRIBUTOR_BONUS,
            _CONTRIBUTOR_BONUS_CAP,
        )
        score += bonus
        supporting.append(
            f"{signals.human_contributor_count} human contributor(s) documented"
        )

    score = round(max(0.0, min(1.0, score)), 4)
    return CopyrightReadinessResult(
        score=score,
        label=_readiness_label(score),
        certificate_class=_certificate_class(signals, confirmed_human_fields, ai_tools_present),
        factors_supporting=supporting,
        factors_limiting=limiting,
    )


def _readiness_label(score: float) -> str:
    if score >= _LABEL_STRONG:
        return "strong"
    if score >= _LABEL_MODERATE:
        return "moderate"
    if score >= _LABEL_LIMITED:
        return "limited"
    return "insufficient"


def _certificate_class(
    signals: AuthorshipSignals,
    confirmed_human_fields: int,
    ai_tools_present: bool,
) -> str:
    ai_detected = (signals.ai_detection_score or 0.0) >= _AI_DETECTED_THRESHOLD
    has_ai = ai_detected or ai_tools_present or signals.is_ai_disclosed is True

    if (signals.human_contributor_count or 0) > 1:
        return "live_split"

    if not has_ai:
        return "standard"

    human_led = (
        signals.ai_modification_by_human is True
        and signals.human_creative_direction is True
    )
    if human_led:
        return "ai_assisted"

    if confirmed_human_fields > 0:
        return "hybrid_authorship"

    return "ai_assisted"
