"""
Metadata Intelligence — Commit 4: Metadata Anomaly Intelligence Engine.

A deterministic, rule-based anomaly engine that inspects the PERSISTED metadata
layers (raw / normalized / derived) and flags structural inconsistencies. Like
the trust score engine it is a pure function of its inputs — no I/O, no DB, no
network, and NO AI models or unexplainable heuristics. Every flag it raises is
produced by an explicit, auditable rule and carries a human-readable reason.

Scope: anomaly flagging ONLY. No deepfake / watermark / forensic detection, no
duplicate-asset intelligence — those belong to a later commit.

Thirteen rules across seven categories:

    Timestamp            timestamp_order_reversed (Medium)
                         timestamp_future         (High)
                         timestamp_missing        (Low)
    Metadata Stripping   exif_stripped            (High)
                         creator_missing          (Medium)
                         gps_removed              (Low)
    Container            mime_mismatch            (High)
                         extension_mismatch       (Medium)
    Hash                 hash_missing             (Medium)
                         hash_malformed           (High)
    GPS                  gps_impossible_coordinates (High)
                         gps_partial              (Low)
    Software             software_conflict        (Medium)

Scoring: each flag contributes severity points (High=30, Medium=15, Low=5); the
anomaly score is the sum clamped to [0, 100]. A higher anomaly score means more
/ more severe structural anomalies were detected.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# Single source of truth for the anomaly engine version. Any change to the rule
# set or scoring that alters outputs must bump this version.
ANOMALY_ENGINE_VERSION = "1.0.0"

# Severity -> points. Sum of flag points, clamped to [0, 100], is the score.
SEVERITY_POINTS: Dict[str, int] = {"High": 30, "Medium": 15, "Low": 5}


# ── Small pure helpers ─────────────────────────────────────────────────────────

def _section(normalized: Dict[str, Any], name: str) -> Dict[str, Any]:
    sec = (normalized or {}).get(name)
    return sec if isinstance(sec, dict) else {}


def _meaningful(value: Any) -> bool:
    """True when ``value`` carries real content (not None / "" / False / empty)."""
    if value is None or value is False:
        return False
    if isinstance(value, str):
        return value.strip() != ""
    if isinstance(value, dict):
        return any(_meaningful(v) for v in value.values())
    if isinstance(value, (list, tuple, set)):
        return any(_meaningful(v) for v in value)
    if isinstance(value, (int, float)):
        return True
    return bool(value)


def _first(section: Dict[str, Any], *keys: str) -> Optional[str]:
    for k in keys:
        v = section.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
        if v not in (None, "", {}, [], False):
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


def _mime(normalized: Dict[str, Any], section: str) -> Optional[str]:
    return _first(_section(normalized, section), "mime_type", "mime")


def _effective_mime(normalized: Dict[str, Any],
                    mime_type: Optional[str]) -> Optional[str]:
    """Best available MIME: explicit arg, else file section, else container."""
    if mime_type and isinstance(mime_type, str) and mime_type.strip():
        return mime_type.strip()
    return _mime(normalized, "file") or _mime(normalized, "container")


def _is_image(normalized: Dict[str, Any], mime_type: Optional[str]) -> bool:
    m = _effective_mime(normalized, mime_type)
    return bool(m) and m.lower().startswith("image/")


def _is_image_or_pdf(normalized: Dict[str, Any], mime_type: Optional[str]) -> bool:
    m = _effective_mime(normalized, mime_type)
    if not m:
        return False
    m = m.lower()
    return m.startswith("image/") or m == "application/pdf" or m.endswith("/pdf")


def _flag(flag: str, category: str, severity: str, reason: str,
          affected_fields: List[str], recommended_action: str) -> Dict[str, Any]:
    return {
        "flag": flag,
        "category": category,
        "severity": severity,
        "reason": reason,
        "affected_fields": affected_fields,
        "recommended_action": recommended_action,
    }


# ── Individual rule checks (each returns a flag dict or None) ────────────────────

def _rule_timestamp_order_reversed(normalized) -> Optional[Dict[str, Any]]:
    ts = _section(normalized, "timestamps")
    created = _first(ts, "created", "create_date", "creation_date")
    modified = _first(ts, "modified", "modify_date", "modification_date")
    # Lexicographic comparison is valid + deterministic for the canonical
    # "YYYY:MM:DD HH:MM:SS" / ISO-8601 forms produced by extraction.
    if created and modified and created > modified:
        return _flag(
            "timestamp_order_reversed", "Timestamp", "Medium",
            f"Creation timestamp ({created}) is later than the modification "
            f"timestamp ({modified}).",
            ["timestamps.created", "timestamps.modified"],
            "Verify the capture/edit history; reversed order can indicate "
            "tampering or an incorrect device clock.",
        )
    return None


def _rule_timestamp_future(normalized) -> Optional[Dict[str, Any]]:
    ts = _section(normalized, "timestamps")
    current_year = datetime.now(timezone.utc).year
    offenders: List[str] = []
    for key in ("created", "modified", "encoded", "digitized"):
        val = ts.get(key)
        if isinstance(val, str) and len(val) >= 4 and val[:4].isdigit():
            if int(val[:4]) > current_year:
                offenders.append(f"timestamps.{key}")
    if offenders:
        return _flag(
            "timestamp_future", "Timestamp", "High",
            f"One or more timestamps are dated beyond the current year "
            f"({current_year}).",
            offenders,
            "Reject or re-verify: a future timestamp is physically impossible "
            "and strongly indicates manipulation or a corrupt clock.",
        )
    return None


def _rule_timestamp_missing(normalized, mime_type) -> Optional[Dict[str, Any]]:
    if not _is_image_or_pdf(normalized, mime_type):
        return None
    ts = _section(normalized, "timestamps")
    if not any(_meaningful(v) for v in ts.values()):
        return _flag(
            "timestamp_missing", "Timestamp", "Low",
            "No creation/modification timestamps are present for an image or "
            "PDF asset that would normally carry them.",
            ["timestamps"],
            "Treat provenance as weaker; request the original file if temporal "
            "provenance matters.",
        )
    return None


def _rule_exif_stripped(normalized, mime_type) -> Optional[Dict[str, Any]]:
    if not _is_image(normalized, mime_type):
        return None
    camera = _section(normalized, "camera")
    exif = _section(normalized, "exif")
    gps = _section(normalized, "gps")
    if (not _meaningful(camera) and not _meaningful(exif)
            and not _meaningful(gps)):
        return _flag(
            "exif_stripped", "Metadata Stripping", "High",
            "The image carries no camera, EXIF or GPS metadata — the EXIF block "
            "appears to have been stripped.",
            ["camera", "exif", "gps"],
            "Request the original capture; a fully stripped EXIF block removes "
            "device provenance and is common after re-export or laundering.",
        )
    return None


def _rule_creator_missing(normalized) -> Optional[Dict[str, Any]]:
    camera = _section(normalized, "camera")
    copyright_ = _section(normalized, "copyright")
    software = _section(normalized, "software")
    audio = _section(normalized, "audio_tags")
    signal = (
        _first(camera, "make", "model")
        or _first(copyright_, "creator", "artist", "copyright_owner",
                  "copyright", "author", "rights")
        or _first(software, "editing_software", "creator_tool", "software")
        or _first(audio, "artist", "album_artist", "composer")
    )
    if not signal:
        return _flag(
            "creator_missing", "Creator", "Medium",
            "No creator, ownership or device-attribution signal is present "
            "(camera make/model, copyright/creator, editing software, or "
            "audio artist).",
            ["camera.make", "copyright.creator", "software.editing_software",
             "audio_tags.artist"],
            "Attach attribution before certification; anonymous assets carry "
            "weaker provenance.",
        )
    return None


def _rule_gps_removed(raw, normalized, mime_type) -> Optional[Dict[str, Any]]:
    # Fires ONLY when GPS keys existed in the raw extractor output but the
    # normalized GPS section carries no usable coordinates — i.e. GPS was
    # present and then removed/lost. Merely-absent GPS is NOT an anomaly.
    if not _is_image(normalized, mime_type):
        return None
    raw_has_gps = any("gps" in str(k).lower() for k in (raw or {}).keys())
    if not raw_has_gps:
        return None
    gps = _section(normalized, "gps")
    has_coords = _meaningful(gps.get("latitude")) or _meaningful(gps.get("longitude"))
    if not has_coords:
        return _flag(
            "gps_removed", "GPS", "Low",
            "GPS keys are present in the raw metadata but no usable coordinates "
            "survived normalization — location data appears to have been removed.",
            ["gps.latitude", "gps.longitude"],
            "Confirm whether GPS was intentionally scrubbed; note the location "
            "provenance gap.",
        )
    return None


def _rule_mime_mismatch(normalized) -> Optional[Dict[str, Any]]:
    f_mime = _mime(normalized, "file")
    c_mime = _mime(normalized, "container")
    if f_mime and c_mime and f_mime.lower() != c_mime.lower():
        return _flag(
            "mime_mismatch", "Container", "High",
            f"The file-level MIME type ({f_mime}) does not match the container "
            f"MIME type ({c_mime}).",
            ["file.mime_type", "container.mime_type"],
            "Reject or re-verify: a MIME mismatch can indicate a disguised or "
            "misrepresented file type.",
        )
    return None


def _rule_extension_mismatch(normalized) -> Optional[Dict[str, Any]]:
    f_ext = _first(_section(normalized, "file"), "extension", "ext")
    c_ext = _first(_section(normalized, "container"), "extension", "ext")
    if f_ext and c_ext and f_ext.lower() != c_ext.lower():
        return _flag(
            "extension_mismatch", "Container", "Medium",
            f"The file extension ({f_ext}) does not match the container's "
            f"detected extension ({c_ext}).",
            ["file.extension", "container.extension"],
            "Verify the true format; a mismatched extension can indicate a "
            "renamed or misrepresented file.",
        )
    return None


def _rule_hash_missing(normalized) -> Optional[Dict[str, Any]]:
    # hash_missing is defined on SHA-256 only (MD5 is commonly absent and is
    # not required for integrity here).
    hashes = _section(normalized, "hashes")
    if not _is_hex(hashes.get("sha256"), 64):
        return _flag(
            "hash_missing", "Hash", "Medium",
            "No valid SHA-256 fingerprint is present for the asset.",
            ["hashes.sha256"],
            "Recompute and persist the SHA-256; integrity cannot be verified "
            "without it.",
        )
    return None


def _rule_hash_malformed(normalized) -> Optional[Dict[str, Any]]:
    # Fires when a hash value IS present but has the wrong length/charset.
    hashes = _section(normalized, "hashes")
    bad: List[str] = []
    sha = hashes.get("sha256")
    md5 = hashes.get("md5")
    if _meaningful(sha) and not _is_hex(sha, 64):
        bad.append("hashes.sha256")
    if _meaningful(md5) and not _is_hex(md5, 32):
        bad.append("hashes.md5")
    if bad:
        return _flag(
            "hash_malformed", "Hash", "High",
            "A cryptographic hash is present but malformed (wrong length or "
            "non-hex characters).",
            bad,
            "Recompute the affected hash; a malformed digest cannot be trusted "
            "for integrity verification.",
        )
    return None


def _rule_gps_impossible_coordinates(normalized) -> Optional[Dict[str, Any]]:
    gps = _section(normalized, "gps")
    lat = gps.get("latitude")
    lon = gps.get("longitude")

    def _num(v):
        if isinstance(v, (int, float)):
            return float(v)
        if isinstance(v, str):
            try:
                return float(v.strip())
            except ValueError:
                return None
        return None

    lat_n, lon_n = _num(lat), _num(lon)
    if lat_n is None:
        return None
    if abs(lat_n) > 90 or (lon_n is not None and abs(lon_n) > 180):
        return _flag(
            "gps_impossible_coordinates", "GPS", "High",
            f"GPS coordinates are out of range (latitude {lat_n}, longitude "
            f"{lon_n}); valid latitude is ±90 and longitude ±180.",
            ["gps.latitude", "gps.longitude"],
            "Reject the location metadata; impossible coordinates indicate "
            "corruption or fabrication.",
        )
    return None


def _rule_gps_partial(normalized) -> Optional[Dict[str, Any]]:
    gps = _section(normalized, "gps")
    has_lat = _meaningful(gps.get("latitude"))
    has_lon = _meaningful(gps.get("longitude"))
    if has_lat != has_lon:  # exactly one present
        present = "latitude" if has_lat else "longitude"
        return _flag(
            "gps_partial", "GPS", "Low",
            f"Only one GPS coordinate is present ({present}); a complete fix "
            f"requires both latitude and longitude.",
            ["gps.latitude", "gps.longitude"],
            "Treat the location as unreliable; a partial coordinate cannot be "
            "mapped.",
        )
    return None


def _rule_software_conflict(normalized) -> Optional[Dict[str, Any]]:
    software = _section(normalized, "software")
    camera = _section(normalized, "camera")
    editor = _first(software, "editing_software", "creator_tool",
                    "export_application", "software") or ""
    editor_l = editor.lower()
    edited = "photoshop" in editor_l or "lightroom" in editor_l
    if edited and not _first(camera, "make", "model"):
        return _flag(
            "software_conflict", "Software", "Medium",
            f"Editing software ({editor}) is recorded but no originating camera "
            f"device is present — the processing history is inconsistent.",
            ["software.editing_software", "camera.make"],
            "Investigate provenance; edited output with no capture device can "
            "indicate a synthetic or laundered origin.",
        )
    return None


# ── Public entry point ─────────────────────────────────────────────────────────

def compute_metadata_anomaly_score(
    *,
    raw: Optional[Dict[str, Any]] = None,
    normalized: Optional[Dict[str, Any]] = None,
    derived: Optional[Dict[str, Any]] = None,
    mime_type: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Compute the deterministic metadata anomaly score from the persisted layers.

    Returns::

        {
          "anomaly_score": 45,
          "flags": [ {flag, category, severity, reason, affected_fields,
                      recommended_action}, ... ],
          "anomaly_summary": "3 anomaly flag(s) detected: ...",
          "engine_version": "1.0.0"
        }

    Safe on missing / partial / empty inputs — every rule degrades gracefully
    rather than raising. Both the flag list and the score are deterministic
    functions of the input, so identical metadata always yields an identical
    result (including flag ordering, which follows the fixed rule order below).
    """
    raw = raw or {}
    normalized = normalized or {}
    derived = derived or {}

    checks = [
        _rule_timestamp_order_reversed(normalized),
        _rule_timestamp_future(normalized),
        _rule_timestamp_missing(normalized, mime_type),
        _rule_exif_stripped(normalized, mime_type),
        _rule_creator_missing(normalized),
        _rule_gps_removed(raw, normalized, mime_type),
        _rule_mime_mismatch(normalized),
        _rule_extension_mismatch(normalized),
        _rule_hash_missing(normalized),
        _rule_hash_malformed(normalized),
        _rule_gps_impossible_coordinates(normalized),
        _rule_gps_partial(normalized),
        _rule_software_conflict(normalized),
    ]
    flags = [c for c in checks if c is not None]

    score = sum(SEVERITY_POINTS.get(f["severity"], 0) for f in flags)
    score = max(0, min(100, score))

    if not flags:
        summary = "No anomalies detected."
    else:
        listed = ", ".join(f"{f['flag']} ({f['severity']})" for f in flags)
        summary = f"{len(flags)} anomaly flag(s) detected: {listed}."

    return {
        "anomaly_score": score,
        "flags": flags,
        "anomaly_summary": summary,
        "engine_version": ANOMALY_ENGINE_VERSION,
    }
