"""
Certificate Class System — Omni Veil Copyright Readiness Infrastructure

Four certificate classes, each producing three mandatory sections:
  A. Human Creative Contributions  — what humans did
  B. AI-Assisted Contributions     — what AI tools did
  C. Ownership Splits              — who legally owns (separate from creative %)

REQUIRED LEGAL DISCLAIMER appears on every certificate.
"""

from dataclasses import dataclass, field
from typing import Optional, List
from app.services.copyright_readiness import CopyrightReadinessResult, LEGAL_DISCLAIMER

# ── Certificate class catalogue ────────────────────────────────────────────────

CERTIFICATE_CLASSES = {
    "standard": {
        "label": "Standard Authorship Certificate",
        "description": "Fully human-authored work with no AI tools used or detected.",
    },
    "hybrid_authorship": {
        "label": "Hybrid Authorship Certificate",
        "description": "Human and AI collaborated; human creative contributions are documented alongside AI tool usage.",
    },
    "live_split": {
        "label": "Live-Split Authorship Certificate",
        "description": "Multi-contributor session with documented creative, ownership, and AI-assisted percentages per contributor.",
    },
    "ai_assisted": {
        "label": "AI-Assisted Authorship Certificate",
        "description": "AI tools were used under human creative direction; human modification of AI output is documented.",
    },
}

# Ordered list of all human authorship form types
_HUMAN_CONTRIBUTION_TYPES = [
    ("creative_direction", "Human creative direction"),
    ("editing",            "Human editing"),
    ("arrangement",        "Human arrangement"),
    ("lyrics",             "Human lyrics"),
    ("performance",        "Human performance"),
    ("transformation",     "Human transformation"),
]


# ── Input context ──────────────────────────────────────────────────────────────

@dataclass
class CertificateContext:
    """All data needed to build any of the four certificate classes."""
    cert_id: str
    omni_id: str
    asset_id: str
    issued_at: str          # ISO-8601
    filename: str
    sha256: str
    blake3: str
    trust_score: float
    content_label: str
    copyright_readiness: CopyrightReadinessResult

    # Provenance / ownership
    creator_name: Optional[str] = None
    copyright_owner: Optional[str] = None
    license_type: Optional[str] = None
    ai_disclosure: Optional[str] = None    # "human" | "ai" | "mixed" | None

    # Human authorship evidence
    human_creative_direction: Optional[bool] = None
    human_editing_present: Optional[bool] = None
    human_arrangement_present: Optional[bool] = None
    human_lyrics_present: Optional[bool] = None
    human_performance_present: Optional[bool] = None
    human_transformation_present: Optional[bool] = None
    human_authorship_summary: Optional[str] = None

    # AI-assisted contributions
    ai_tools_used: List[str] = field(default_factory=list)
    ai_disclosure_complete: Optional[bool] = None
    ai_modification_by_human: Optional[bool] = None
    ai_detection_score: Optional[float] = None

    # Contributors — used by live_split class
    # Each dict: {name, role, creative_contribution_pct, ownership_split_pct, ai_assisted_pct}
    contributors: List[dict] = field(default_factory=list)


# ── Public builder ─────────────────────────────────────────────────────────────

def build_certificate(ctx: CertificateContext) -> dict:
    """
    Return a structured certificate dict for the given class.

    The result must be signed by the caller (ingest.py / sign_certificate).
    All four classes produce the same top-level shape; sections A, B, C are
    always present but populated according to the class rules.
    """
    cert_class = ctx.copyright_readiness.certificate_class
    class_meta = CERTIFICATE_CLASSES.get(cert_class, CERTIFICATE_CLASSES["standard"])

    section_a = _build_section_a(ctx, cert_class)
    section_b = _build_section_b(ctx, cert_class)
    section_c = _build_section_c(ctx, cert_class)

    return {
        # ── Identity ────────────────────────────────────────────────────────
        "cert_id": ctx.cert_id,
        "omni_id": ctx.omni_id,
        "asset_id": ctx.asset_id,
        "issuer": "Omni Veil Trust OS",
        "certificate_class": cert_class,
        "certificate_class_label": class_meta["label"],
        "certificate_class_description": class_meta["description"],
        "subject_name": ctx.creator_name or "Unknown",
        "issued_at": ctx.issued_at,
        "filename": ctx.filename,

        # ── Cryptographic fingerprints ──────────────────────────────────────
        "sha256": ctx.sha256,
        "blake3": ctx.blake3,

        # ── Trust & classification ──────────────────────────────────────────
        "trust_score": ctx.trust_score,
        "content_label": ctx.content_label,
        "ai_disclosure": ctx.ai_disclosure,
        "copyright_owner": ctx.copyright_owner or "",
        "license_type": ctx.license_type or "",

        # ── Copyright readiness (authorship support infrastructure) ─────────
        "copyright_readiness": {
            "score": ctx.copyright_readiness.score,
            "label": ctx.copyright_readiness.label,
            "certificate_class": cert_class,
            "factors_supporting": ctx.copyright_readiness.factors_supporting,
            "factors_limiting": ctx.copyright_readiness.factors_limiting,
        },

        # ── Section A: Human Creative Contributions ─────────────────────────
        "section_a_human_contributions": section_a,

        # ── Section B: AI-Assisted Contributions ────────────────────────────
        "section_b_ai_contributions": section_b,

        # ── Section C: Ownership Splits ─────────────────────────────────────
        "section_c_ownership_splits": section_c,

        # ── Required legal disclaimer ────────────────────────────────────────
        "legal_disclaimer": LEGAL_DISCLAIMER,
    }


# ── Section builders ───────────────────────────────────────────────────────────

def _build_section_a(ctx: CertificateContext, cert_class: str) -> dict:
    """
    Section A — Human Creative Contributions.
    Documents what humans did, not who owns it.
    """
    field_values = [
        ctx.human_creative_direction,
        ctx.human_editing_present,
        ctx.human_arrangement_present,
        ctx.human_lyrics_present,
        ctx.human_performance_present,
        ctx.human_transformation_present,
    ]

    contributions = []
    for (type_key, type_label), present in zip(_HUMAN_CONTRIBUTION_TYPES, field_values):
        if present is not None:
            contributions.append({
                "type": type_key,
                "label": type_label,
                "present": present,
            })

    # For standard certificates confirm all human, no AI
    if cert_class == "standard" and not contributions:
        contributions = [
            {"type": type_key, "label": label, "present": True}
            for type_key, label in _HUMAN_CONTRIBUTION_TYPES[:3]  # direction, editing, arrangement
        ]

    # Per-contributor creative breakdown (populated for live_split)
    contributor_rows = []
    for c in ctx.contributors:
        row: dict = {
            "contributor_name": c.get("name", "Unknown"),
            "role": c.get("role"),
        }
        if c.get("creative_contribution_pct") is not None:
            row["creative_contribution_pct"] = c["creative_contribution_pct"]
        contributor_rows.append(row)

    # Fall back to primary creator if no contributor rows
    if not contributor_rows and ctx.creator_name:
        contributor_rows.append({
            "contributor_name": ctx.creator_name,
            "role": "primary creator",
        })

    return {
        "section": "A",
        "label": "Human Creative Contributions",
        "description": "Creative work performed by human author(s) — not an ownership declaration.",
        "contributions": contributions,
        "contributors": contributor_rows,
        "summary": ctx.human_authorship_summary or "",
    }


def _build_section_b(ctx: CertificateContext, cert_class: str) -> dict:
    """
    Section B — AI-Assisted Contributions.
    Documents what AI tools did.  Empty for 'standard' certificates.
    """
    if cert_class == "standard":
        return {
            "section": "B",
            "label": "AI-Assisted Contributions",
            "description": "No AI tools used or detected.",
            "ai_tools_used": [],
            "ai_disclosure_complete": None,
            "ai_modification_by_human": None,
            "ai_detection_score": None,
        }

    detection_pct = (
        round(ctx.ai_detection_score * 100, 1)
        if ctx.ai_detection_score is not None
        else None
    )

    section: dict = {
        "section": "B",
        "label": "AI-Assisted Contributions",
        "description": "Portions of this work generated or assisted by AI tools.",
        "ai_tools_used": ctx.ai_tools_used or [],
        "ai_disclosure_complete": ctx.ai_disclosure_complete,
        "ai_modification_by_human": ctx.ai_modification_by_human,
        "ai_detection_score": ctx.ai_detection_score,
        "ai_detection_pct": detection_pct,
    }

    # Class-specific notes
    if cert_class == "ai_assisted":
        section["note"] = (
            "AI tools were used under human creative direction. "
            "Human modification of AI output has been documented."
        )
    elif cert_class == "hybrid_authorship":
        section["note"] = (
            "AI tools contributed to the creative output alongside human authorship. "
            "Both human and AI contributions are documented separately."
        )
    elif cert_class == "live_split":
        section["note"] = (
            "AI tool usage per contributor is reflected in the AI-Assisted % "
            "column of Section C."
        )

    return section


def _build_section_c(ctx: CertificateContext, cert_class: str) -> dict:
    """
    Section C — Ownership Splits.
    Legal ownership declarations, entirely separate from creative contribution %.
    For live_split: three columns per row (creative %, ownership %, AI-assisted %).
    """
    note = (
        "Ownership splits represent legal ownership declarations and are separate "
        "from creative contribution percentages."
    )

    if cert_class == "live_split" and ctx.contributors:
        splits = []
        for c in ctx.contributors:
            splits.append({
                "contributor_name": c.get("name", "Unknown"),
                "role": c.get("role"),
                "creative_contribution_pct": c.get("creative_contribution_pct"),
                "ownership_split_pct": c.get("ownership_split_pct") or c.get("split_percentage"),
                "ai_assisted_pct": c.get("ai_assisted_pct"),
            })
        return {
            "section": "C",
            "label": "Ownership Splits",
            "description": "Legal ownership per contributor with creative and AI-assisted percentages.",
            "note": note,
            "columns": ["contributor_name", "role", "creative_contribution_pct",
                        "ownership_split_pct", "ai_assisted_pct"],
            "splits": splits,
            "copyright_owner": ctx.copyright_owner or "",
        }

    # Single-owner certificate (standard, hybrid_authorship, ai_assisted)
    split_row: dict = {
        "contributor_name": ctx.copyright_owner or ctx.creator_name or "Unknown",
        "role": "copyright owner",
        "ownership_split_pct": 100.0,
    }
    if cert_class != "standard":
        split_row["creative_contribution_pct"] = None   # not declared in single-owner path
        split_row["ai_assisted_pct"] = None

    return {
        "section": "C",
        "label": "Ownership Splits",
        "description": "Legal ownership declaration — separate from creative contribution.",
        "note": note,
        "columns": ["contributor_name", "role", "ownership_split_pct"],
        "splits": [split_row],
        "copyright_owner": ctx.copyright_owner or "",
    }
