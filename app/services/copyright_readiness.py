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

# Readiness label thresholds
_LABEL_STRONG = 0.75
_LABEL_MODERATE = 0.50
_LABEL_LIMITED = 0.25


@dataclass
class AuthorshipSignals:
    """
    All inputs consumed by compute_copyright_readiness().

    Callers populate whichever fields are known; None means "not assessed."
    Boolean fields should be True only when positively confirmed — not assumed.
    """
    # Human creative contribution flags (one per authorship form)
    human_creative_direction: Optional[bool] = None
    human_editing_present: Optional[bool] = None
    human_arrangement_present: Optional[bool] = None
    human_lyrics_present: Optional[bool] = None
    human_performance_present: Optional[bool] = None
    human_transformation_present: Optional[bool] = None

    # AI disclosure fields
    ai_disclosure_complete: Optional[bool] = None   # full AI tool list submitted
    ai_tools_used: Optional[List[str]] = field(default_factory=list)
    ai_modification_by_human: Optional[bool] = None  # human edited AI output

    # Detection signals (from Hive or equivalent)
    ai_detection_score: Optional[float] = None      # 0.0 – 1.0 from detection service
    is_ai_disclosed: Optional[bool] = None          # creator's own disclosure flag

    # Contributor signals
    human_contributor_count: Optional[int] = None   # number of human contributors


@dataclass
class CopyrightReadinessResult:
    """
    Output of compute_copyright_readiness().

    score           — float 0.0–1.0, strength of documented human authorship evidence
    label           — strong | moderate | limited | insufficient
    certificate_class — standard | hybrid_authorship | live_split | ai_assisted
    factors_supporting — list of positive evidence strings
    factors_limiting   — list of gaps or negative evidence strings
    legal_disclaimer   — required on every certificate and report
    """
    score: float
    label: str
    certificate_class: str
    factors_supporting: List[str]
    factors_limiting: List[str]
    legal_disclaimer: str = LEGAL_DISCLAIMER


# ── Scoring weights ────────────────────────────────────────────────────────────
# Each confirmed human authorship form contributes equally.
_HUMAN_FIELD_WEIGHT = 0.12          # max 6 × 0.12 = 0.72
_HONEST_AI_DISCLOSURE_BONUS = 0.08  # AI detected AND disclosed
_UNDETECTED_AI_DISCLOSURE_BONUS = 0.05  # no AI detected, disclosure submitted anyway
_HUMAN_MODIFIED_AI_BONUS = 0.08     # human modification of AI output documented
_UNDISCLOSED_AI_PENALTY = -0.20     # AI detected but not disclosed
_NO_HUMAN_FIELDS_PENALTY = -0.10    # zero authorship fields filled
_FULLY_AI_NO_HUMAN_PENALTY = -0.20  # high AI score + zero human + no modification
_PER_CONTRIBUTOR_BONUS = 0.03       # per human contributor, capped at 0.09

_AI_DETECTED_THRESHOLD = 0.40       # Hive score at which AI is considered detected
_AI_HIGH_CONFIDENCE = 0.85          # Hive score at which content is "fully AI"
_CONTRIBUTOR_BONUS_CAP = 0.09


def compute_copyright_readiness(signals: AuthorshipSignals) -> CopyrightReadinessResult:
    """
    Compute the copyright readiness score and derive label + certificate class.

    The score reflects only the strength of documented human authorship evidence.
    It does not represent legal copyright status, ownership certainty, or any
    guarantee of copyright approval.
    """
    score = 0.0
    supporting: List[str] = []
    limiting: List[str] = []

    # ── 1. Human authorship contribution fields ────────────────────────────────
    human_field_map = [
        (signals.human_creative_direction,    "Human creative direction documented"),
        (signals.human_editing_present,       "Human editing documented"),
        (signals.human_arrangement_present,   "Human arrangement documented"),
        (signals.human_lyrics_present,        "Human lyrics documented"),
        (signals.human_performance_present,   "Human performance documented"),
        (signals.human_transformation_present,"Human transformation documented"),
    ]

    confirmed_human_fields = sum(1 for val, _ in human_field_map if val is True)

    for val, label in human_field_map:
        if val is True:
            score += _HUMAN_FIELD_WEIGHT
            supporting.append(label)

    if confirmed_human_fields == 0:
        score += _NO_HUMAN_FIELDS_PENALTY
        limiting.append("No human authorship fields documented")

    # ── 2. AI disclosure assessment ────────────────────────────────────────────
    ai_detected = (signals.ai_detection_score or 0.0) >= _AI_DETECTED_THRESHOLD
    ai_disclosed = (
        signals.ai_disclosure_complete is True
        or signals.is_ai_disclosed is True
    )
    ai_tools_present = bool(signals.ai_tools_used)

    if ai_detected and ai_disclosed:
        score += _HONEST_AI_DISCLOSURE_BONUS
        supporting.append("AI use detected and honestly disclosed (supports copyright readiness)")
    elif ai_detected and not ai_disclosed:
        score += _UNDISCLOSED_AI_PENALTY
        limiting.append(
            "AI detected but not disclosed — reduces copyright readiness score"
        )
    elif not ai_detected and ai_disclosed:
        score += _UNDETECTED_AI_DISCLOSURE_BONUS
        supporting.append("AI disclosure completed")

    # ── 3. Human modification of AI content ───────────────────────────────────
    if signals.ai_modification_by_human is True:
        score += _HUMAN_MODIFIED_AI_BONUS
        supporting.append("Human modification of AI-generated content documented")

    # ── 4. Fully AI-generated with no human authorship ────────────────────────
    fully_ai = (signals.ai_detection_score or 0.0) >= _AI_HIGH_CONFIDENCE
    if (
        fully_ai
        and confirmed_human_fields == 0
        and signals.ai_modification_by_human is not True
    ):
        score += _FULLY_AI_NO_HUMAN_PENALTY
        limiting.append(
            "Content appears fully AI-generated with no documented human authorship "
            "or modification"
        )

    # ── 5. Human contributor count ────────────────────────────────────────────
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
    """
    Assign one of the four certificate classes based on authorship composition.

    standard         — fully human, no AI tools detected or declared
    hybrid_authorship — substantial human + AI collaboration
    live_split        — multi-contributor session (any authorship mix)
    ai_assisted       — AI used as a tool; human directed and modified the output
    """
    ai_detected = (signals.ai_detection_score or 0.0) >= _AI_DETECTED_THRESHOLD
    has_ai = ai_detected or ai_tools_present

    # Multi-contributor takes precedence: always a live_split regardless of AI mix
    if (signals.human_contributor_count or 0) > 1:
        return "live_split"

    if not has_ai:
        return "standard"

    # AI is present — distinguish human-led assistance from collaborative hybrid
    human_led = (
        signals.ai_modification_by_human is True
        and signals.human_creative_direction is True
    )
    if human_led:
        return "ai_assisted"

    # AI present + some human authorship documented → hybrid
    if confirmed_human_fields > 0:
        return "hybrid_authorship"

    # AI present, no meaningful human authorship → still ai_assisted (not standard)
    return "ai_assisted"
