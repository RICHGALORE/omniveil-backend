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


# ── Individual factor scorers ───────────────────────────────────────────────────
#
# Each scorer returns ``(fraction, reason)`` where ``fraction`` is in [0, 1] and
# ``reason`` is a truthful, human-readable explanation of exactly what was and
# was not credited. The reason strings are deterministic functions of the input
# so identical metadata always yields identical explanations.

def _score_completeness(normalized: Dict[str, Any]) -> tuple[float, str]:
    present = [name for name in _COMPLETENESS_SECTIONS
               if _is_populated(normalized.get(name))]
    missing = [name for name in _COMPLETENESS_SECTIONS
               if not _is_populated(normalized.get(name))]
    fraction = _clamp01(len(present) / len(_COMPLETENESS_SECTIONS))
    if not missing:
        reason = (f"All {len(_COMPLETENESS_SECTIONS)} canonical metadata "
                  f"sections are populated.")
    else:
        shown = ", ".join(missing[:6]) + ("…" if len(missing) > 6 else "")
        reason = (f"{len(present)}/{len(_COMPLETENESS_SECTIONS)} canonical "
                  f"sections populated; missing: {shown}.")
    return fraction, reason


def _score_consistency(normalized: Dict[str, Any]) -> tuple[float, str]:
    """Internal cross-field agreement. Only applicable checks are counted."""
    file_ = _section(normalized, "file")
    container = _section(normalized, "container")
    hashes = _section(normalized, "hashes")

    applicable = 0
    passed = 0
    failures: list[str] = []

    # 1. Extension agreement (file vs container).
    f_ext = _first_str(file_, "extension", "ext")
    c_ext = _first_str(container, "extension", "ext")
    if f_ext and c_ext:
        applicable += 1
        if f_ext.lower() == c_ext.lower():
            passed += 1
        else:
            failures.append("file/container extension mismatch")

    # 2. MIME agreement (file vs container).
    f_mime = _first_str(file_, "mime_type", "mime")
    c_mime = _first_str(container, "mime_type", "mime")
    if f_mime and c_mime:
        applicable += 1
        if f_mime.lower() == c_mime.lower():
            passed += 1
        else:
            failures.append("file/container MIME mismatch")

    # 3. File size is present and positive (always applicable).
    applicable += 1
    size = file_.get("size", file_.get("size_bytes"))
    if isinstance(size, (int, float)) and size > 0:
        passed += 1
    else:
        failures.append("file size missing or non-positive")

    # 4. MIME is well-formed (always applicable).
    applicable += 1
    if f_mime and "/" in f_mime:
        passed += 1
    else:
        failures.append("MIME type absent or malformed")

    # 5. Primary hash present + well-formed (always applicable).
    applicable += 1
    if _is_hex(hashes.get("sha256"), 64):
        passed += 1
    else:
        failures.append("SHA-256 absent or malformed")

    fraction = _clamp01(passed / applicable) if applicable else 1.0
    if not failures:
        reason = f"All {applicable} applicable cross-field checks agree."
    else:
        reason = (f"{passed}/{applicable} cross-field checks passed; "
                  f"issues: {', '.join(failures)}.")
    return fraction, reason


def _score_hash_integrity(normalized: Dict[str, Any],
                          derived: Dict[str, Any]) -> tuple[float, str]:
    hashes = _section(normalized, "hashes")
    score = 0.0
    present: list[str] = []
    missing: list[str] = []
    if _is_hex(hashes.get("sha256"), 64):
        score += 0.5
        present.append("SHA-256")
    else:
        missing.append("SHA-256")
    if _is_hex(hashes.get("md5"), 32):
        score += 0.25
        present.append("MD5")
    else:
        missing.append("MD5")
    # Deterministic metadata digest computed by the persistence layer.
    if _is_hex(derived.get("metadata_sha256"), 64):
        score += 0.25
        present.append("metadata digest")
    else:
        missing.append("metadata digest")

    if not missing:
        reason = ("SHA-256, MD5 and the deterministic metadata digest are all "
                  "present and well-formed.")
    elif present:
        reason = (f"Present and well-formed: {', '.join(present)}; "
                  f"missing/invalid: {', '.join(missing)}.")
    else:
        reason = "No valid cryptographic fingerprints present."
    return _clamp01(score), reason


def _score_container(normalized: Dict[str, Any]) -> tuple[float, str]:
    container = _section(normalized, "container")
    file_ = _section(normalized, "file")
    score = 0.0
    parts: list[str] = []
    c_mime = _first_str(container, "mime_type", "mime")
    c_ext = _first_str(container, "extension", "ext")
    if c_mime:
        score += 0.4
        parts.append("MIME present")
    else:
        parts.append("MIME missing")
    if c_ext:
        score += 0.3
        parts.append("extension present")
    else:
        parts.append("extension missing")
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
        parts.append("coherent with file identity")
    else:
        parts.append("no file-identity coherence confirmed")
    reason = "Container: " + ", ".join(parts) + "."
    return _clamp01(score), reason


def _score_creator(normalized: Dict[str, Any]) -> tuple[float, str]:
    """Presence of creator / ownership / device attribution signals."""
    copyright_ = _section(normalized, "copyright")
    camera = _section(normalized, "camera")
    software = _section(normalized, "software")
    xmp = _section(normalized, "xmp")
    audio_tags = _section(normalized, "audio_tags")

    labelled = [
        ("copyright/creator", _first_str(copyright_, "creator", "artist",
            "copyright_owner", "copyright", "rights", "author")),
        ("camera device", _first_str(camera, "make", "model")),
        ("software/tool", _first_str(software, "editing_software",
            "creator_tool", "export_application", "software")),
        ("XMP rights", _first_str(xmp, "creator", "rights", "dc:creator",
            "dc:rights")),
        ("audio artist", _first_str(audio_tags, "artist", "album_artist",
            "composer")),
    ]
    present = [name for name, val in labelled if val]
    # Two independent signals -> full credit; one -> half.
    fraction = _clamp01(len(present) / 2.0)
    if present:
        reason = ("Attribution signals present: " + ", ".join(present) +
                  (" (two or more → full credit)." if len(present) >= 2
                   else " (only one → half credit)."))
    else:
        reason = "No creator / ownership / device attribution signals present."
    return fraction, reason


def _score_timestamps(normalized: Dict[str, Any]) -> tuple[float, str]:
    ts = _section(normalized, "timestamps")
    values = [v for v in ts.values() if isinstance(v, str) and v.strip()] \
        if _is_populated(ts) else []
    if not values:
        return 0.0, "No timestamps present in the metadata."

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
            reason = ("Timestamps present and coherent "
                      "(created ≤ modified).")
        else:
            score += 0.25
            reason = ("Timestamps present but inconsistent "
                      "(created is later than modified).")
    else:
        reason = ("At least one timestamp present; created/modified pair "
                  "incomplete, so ordering could not be confirmed.")
    return _clamp01(score), reason


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
          "explanations": {
            "completeness": {"points": 24, "max": 25, "reason": "…"},
            ...
          },
          "engine_version": "1.0.0"
        }

    Safe on missing/partial/empty inputs — every factor degrades gracefully to a
    lower fraction rather than raising. Both ``breakdown`` and ``explanations``
    are deterministic functions of the input, so identical metadata always
    yields an identical result (including reason strings).
    """
    normalized = normalized or {}
    derived = derived or {}
    # ``raw`` is accepted for future factors and interface completeness; the
    # current factor set is driven by the normalized + derived layers.

    scored = {
        "completeness": _score_completeness(normalized),
        "consistency": _score_consistency(normalized),
        "hash_integrity": _score_hash_integrity(normalized, derived),
        "container": _score_container(normalized),
        "creator": _score_creator(normalized),
        "timestamps": _score_timestamps(normalized),
    }

    breakdown = {
        factor: int(round(scored[factor][0] * WEIGHTS[factor]))
        for factor in WEIGHTS
    }
    explanations = {
        factor: {
            "points": breakdown[factor],
            "max": WEIGHTS[factor],
            "reason": scored[factor][1],
        }
        for factor in WEIGHTS
    }
    overall = sum(breakdown.values())
    # Defensive clamp (rounding can never exceed the weight sum, but be safe).
    overall = max(0, min(100, overall))

    return {
        "overall": overall,
        "breakdown": breakdown,
        "explanations": explanations,
        "engine_version": SCORE_ENGINE_VERSION,
    }
