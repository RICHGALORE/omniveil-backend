"""
Metadata Intelligence — Commit 3: Metadata Trust Score Engine.

A deterministic, weighted scoring engine that produces a 0–100 "metadata trust
score" purely from the PERSISTED metadata layers (raw / normalized / derived).
It never re-reads the original uploaded file and performs no I/O — it is a pure
function of its inputs, so identical metadata always yields an identical score.

Scope: scoring ONLY. No AI detection, no anomaly detection, no duplicate-asset
detection — those belong to a later commit.

Weighted factors (weights sum to 100):

    completeness      25   how much of the canonical metadata is populated
    consistency       20   internal cross-field agreement (ext/mime/size/hash)
    hash_integrity    20   presence + validity of cryptographic fingerprints
    container         15   container identity present and coherent with the file
    creator           10   presence of creator / ownership / device attribution
    timestamps        10   presence + ordering coherence of timestamps

Each factor is computed as a fraction in [0, 1] and multiplied by its weight;
the per-factor points are rounded to whole numbers and summed to give the
overall score. The maximum achievable score is 100.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

# Single source of truth for the scoring engine version. Bumping the weights or
# the factor logic in a way that changes outputs must bump this version.
SCORE_ENGINE_VERSION = "1.0.0"

# Factor weights (must sum to 100).
WEIGHTS: Dict[str, int] = {
    "completeness": 25,
    "consistency": 20,
    "hash_integrity": 20,
    "container": 15,
    "creator": 10,
    "timestamps": 10,
}

# Canonical sections considered when measuring completeness. Type-specific
# sections (camera/exif for images, audio_tags for audio) are intentionally
# included so that richer files score higher and sparse files score lower.
_COMPLETENESS_SECTIONS = (
    "file", "technical", "hashes", "container", "codec", "timestamps",
    "camera", "gps", "copyright", "software", "exif", "audio_tags",
    "xmp", "iptc",
)


# ── Small pure helpers ─────────────────────────────────────────────────────────

def _is_populated(value: Any) -> bool:
    """True when ``value`` carries real content (not None / empty / blank)."""
    if value is None:
        return False
    if isinstance(value, str):
        return value.strip() != ""
    if isinstance(value, dict):
        return any(_is_populated(v) for v in value.values())
    if isinstance(value, (list, tuple, set)):
        return any(_is_populated(v) for v in value)
    if isinstance(value, (int, float)):
        return True
    return bool(value)


def _section(normalized: Dict[str, Any], name: str) -> Dict[str, Any]:
    sec = normalized.get(name)
    return sec if isinstance(sec, dict) else {}


def _first_str(section: Dict[str, Any], *keys: str) -> Optional[str]:
    for k in keys:
        v = section.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
        if v not in (None, "", {}, []):
            return str(v)
    return None


def _is_hex(value: Any, length: int) -> bool:
    if not isinstance(value, str):
        return False
    v = value.strip().lower()
    if len(v) != length:
        return False
    try:
        int(v, 16)
        return True
    except ValueError:
        return False


def _clamp01(x: float) -> float:
    return 0.0 if x < 0 else 1.0 if x > 1 else x


# ── Individual factor scorers (each returns a fraction in [0, 1]) ───────────────

def _score_completeness(normalized: Dict[str, Any]) -> float:
    populated = sum(
        1 for name in _COMPLETENESS_SECTIONS
        if _is_populated(normalized.get(name))
    )
    return _clamp01(populated / len(_COMPLETENESS_SECTIONS))


def _score_consistency(normalized: Dict[str, Any]) -> float:
    """Internal cross-field agreement. Only applicable checks are counted."""
    file_ = _section(normalized, "file")
    container = _section(normalized, "container")
    hashes = _section(normalized, "hashes")

    applicable = 0
    passed = 0

    # 1. Extension agreement (file vs container).
    f_ext = _first_str(file_, "extension", "ext")
    c_ext = _first_str(container, "extension", "ext")
    if f_ext and c_ext:
        applicable += 1
        if f_ext.lower() == c_ext.lower():
            passed += 1

    # 2. MIME agreement (file vs container).
    f_mime = _first_str(file_, "mime_type", "mime")
    c_mime = _first_str(container, "mime_type", "mime")
    if f_mime and c_mime:
        applicable += 1
        if f_mime.lower() == c_mime.lower():
            passed += 1

    # 3. File size is present and positive (always applicable).
    applicable += 1
    size = file_.get("size", file_.get("size_bytes"))
    if isinstance(size, (int, float)) and size > 0:
        passed += 1

    # 4. MIME is well-formed (always applicable).
    applicable += 1
    if f_mime and "/" in f_mime:
        passed += 1

    # 5. Primary hash present + well-formed (always applicable).
    applicable += 1
    if _is_hex(hashes.get("sha256"), 64):
        passed += 1

    return _clamp01(passed / applicable) if applicable else 1.0


def _score_hash_integrity(normalized: Dict[str, Any],
                          derived: Dict[str, Any]) -> float:
    hashes = _section(normalized, "hashes")
    score = 0.0
    if _is_hex(hashes.get("sha256"), 64):
        score += 0.5
    if _is_hex(hashes.get("md5"), 32):
        score += 0.25
    # Deterministic metadata digest computed by the persistence layer.
    if _is_hex(derived.get("metadata_sha256"), 64):
        score += 0.25
    return _clamp01(score)


def _score_container(normalized: Dict[str, Any]) -> float:
    container = _section(normalized, "container")
    file_ = _section(normalized, "file")
    score = 0.0
    c_mime = _first_str(container, "mime_type", "mime")
    c_ext = _first_str(container, "extension", "ext")
    if c_mime:
        score += 0.4
    if c_ext:
        score += 0.3
    # Coherence with the file-level identity.
    f_mime = _first_str(file_, "mime_type", "mime")
    f_ext = _first_str(file_, "extension", "ext")
    coherent = False
    if c_mime and f_mime and c_mime.lower() == f_mime.lower():
        coherent = True
    elif c_ext and f_ext and c_ext.lower() == f_ext.lower():
        coherent = True
    if coherent:
        score += 0.3
    return _clamp01(score)


def _score_creator(normalized: Dict[str, Any]) -> float:
    """Presence of creator / ownership / device attribution signals."""
    copyright_ = _section(normalized, "copyright")
    camera = _section(normalized, "camera")
    software = _section(normalized, "software")
    xmp = _section(normalized, "xmp")
    audio_tags = _section(normalized, "audio_tags")

    signals = [
        _first_str(copyright_, "creator", "artist", "copyright_owner",
                   "copyright", "rights", "author"),
        _first_str(camera, "make", "model"),
        _first_str(software, "editing_software", "creator_tool",
                   "export_application", "software"),
        _first_str(xmp, "creator", "rights", "dc:creator", "dc:rights"),
        _first_str(audio_tags, "artist", "album_artist", "composer"),
    ]
    present = sum(1 for s in signals if s)
    # Two independent signals -> full credit; one -> half.
    return _clamp01(present / 2.0)


def _score_timestamps(normalized: Dict[str, Any]) -> float:
    ts = _section(normalized, "timestamps")
    if not _is_populated(ts):
        return 0.0

    values = [v for v in ts.values() if isinstance(v, str) and v.strip()]
    if not values:
        return 0.0

    score = 0.5  # at least one timestamp present

    created = _first_str(ts, "created", "create_date", "date_created",
                         "creation_date")
    modified = _first_str(ts, "modified", "modify_date", "date_modified",
                         "modification_date")
    if created and modified:
        # Lexicographic comparison is correct for ISO-8601 timestamps and is
        # fully deterministic; if they are not comparable we still credit the
        # presence of two distinct timestamps.
        if created <= modified:
            score += 0.5
        else:
            score += 0.25
    return _clamp01(score)


# ── Public entry point ─────────────────────────────────────────────────────────

def compute_metadata_trust_score(
    *,
    raw: Optional[Dict[str, Any]] = None,
    normalized: Optional[Dict[str, Any]] = None,
    derived: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Compute the deterministic metadata trust score from the persisted layers.

    Returns::

        {
          "overall": 92,
          "breakdown": {
            "completeness": 24, "consistency": 19, "hash_integrity": 20,
            "container": 14, "creator": 8, "timestamps": 7
          },
          "engine_version": "1.0.0"
        }

    Safe on missing/partial/empty inputs — every factor degrades gracefully to a
    lower fraction rather than raising.
    """
    normalized = normalized or {}
    derived = derived or {}
    # ``raw`` is accepted for future factors and interface completeness; the
    # current factor set is driven by the normalized + derived layers.

    fractions = {
        "completeness": _score_completeness(normalized),
        "consistency": _score_consistency(normalized),
        "hash_integrity": _score_hash_integrity(normalized, derived),
        "container": _score_container(normalized),
        "creator": _score_creator(normalized),
        "timestamps": _score_timestamps(normalized),
    }

    breakdown = {
        factor: int(round(fractions[factor] * WEIGHTS[factor]))
        for factor in WEIGHTS
    }
    overall = sum(breakdown.values())
    # Defensive clamp (rounding can never exceed the weight sum, but be safe).
    overall = max(0, min(100, overall))

    return {
        "overall": overall,
        "breakdown": breakdown,
        "engine_version": SCORE_ENGINE_VERSION,
    }
