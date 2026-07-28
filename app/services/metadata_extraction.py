"""
Metadata Intelligence Engine — Commit 1: Extraction Service.

Stateless service that extracts comprehensive metadata from an uploaded asset
and returns a normalized JSON structure. It prefers ExifTool when the binary is
available on the host, and otherwise falls back to the pure-Python extractors
already present in the repository (exifread / mutagen / pypdf / Pillow /
imagehash). No upload ever fails because ExifTool is unavailable.

This commit performs extraction ONLY. It does not persist anything, does not
touch the database, registry, certificates, verify page, or trust scoring.

Normalized top-level sections returned:
    file, technical, codec, container, timestamps, camera, gps, location,
    copyright, software, audio_tags, exif, iptc, xmp, hashes, raw_metadata
plus the envelope fields: extractor, exiftool_available, supported,
duration_ms, warnings.

``location`` is retained as a backward-compatible alias of ``gps`` for existing
consumers; ``gps`` is the canonical section going forward.
"""
from __future__ import annotations

import hashlib
import io
import json
import logging
import os
import shutil
import subprocess
import tempfile
import time
from typing import Any, Dict, Optional

logger = logging.getLogger("omniveil.metadata")

# ── Engine identity ───────────────────────────────────────────────────────────
# Single source of truth for the Metadata Intelligence engine name and version.
# Every persisted metadata record stamps these values; do not duplicate the
# literals elsewhere — import them from here.
ENGINE_NAME = "Omni Veil Metadata Intelligence"
ENGINE_VERSION = "1.0.0"

# ── Supported file types ────────────────────────────────────────────────────
# Extension -> canonical mime type. Used for classification and to decide
# whether a file is "supported" for rich extraction.
SUPPORTED_TYPES: Dict[str, str] = {
    # Images
    "jpg": "image/jpeg", "jpeg": "image/jpeg", "png": "image/png",
    "heic": "image/heic", "heif": "image/heif", "tif": "image/tiff",
    "tiff": "image/tiff", "webp": "image/webp",
    # Video
    "mp4": "video/mp4", "mov": "video/quicktime", "avi": "video/x-msvideo",
    "mkv": "video/x-matroska",
    # Audio
    "mp3": "audio/mpeg", "wav": "audio/x-wav", "aif": "audio/aiff",
    "aiff": "audio/aiff", "flac": "audio/flac", "aac": "audio/aac",
    "m4a": "audio/mp4",
    # Documents
    "pdf": "application/pdf",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
}

IMAGE_EXTS = {"jpg", "jpeg", "png", "heic", "heif", "tif", "tiff", "webp"}
VIDEO_EXTS = {"mp4", "mov", "avi", "mkv"}
AUDIO_EXTS = {"mp3", "wav", "aif", "aiff", "flac", "aac", "m4a"}
DOC_EXTS = {"pdf", "docx", "pptx", "xlsx"}

# ExifTool group prefixes (with -G) mapped onto our normalized blocks.
_EXIF_GROUPS = {"EXIF", "IFD0", "IFD1", "MAKERNOTES", "EXIFIFD", "SUBIFD"}
_IPTC_GROUPS = {"IPTC"}
_XMP_GROUPS = {"XMP", "XMP-DC", "XMP-XMP", "XMP-PHOTOSHOP", "XMP-RIGHTS"}
_AUDIO_GROUPS = {"ID3", "ID3V1", "ID3V2", "VORBIS", "APE", "MPC"}
_GPS_GROUPS = {"GPS"}

# ID3 / common tag frame -> friendly audio-tag name.
_AUDIO_TAG_MAP = {
    "tit2": "title", "title": "title",
    "tpe1": "artist", "artist": "artist",
    "talb": "album", "album": "album",
    "tcon": "genre", "genre": "genre",
    "tdrc": "year", "tyer": "year", "date": "year", "year": "year",
    "trck": "track", "tracknumber": "track", "track": "track",
    "comm": "comment", "comment": "comment",
    "tpe2": "album_artist", "albumartist": "album_artist",
    "tcom": "composer", "composer": "composer",
}


def exiftool_available() -> bool:
    """Return True if the ExifTool binary is on PATH."""
    return shutil.which("exiftool") is not None


# ── Public entry point ────────────────────────────────────────────────────────

def extract_metadata_service(
    data: bytes,
    filename: Optional[str] = None,
    mime_type: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Extract normalized metadata from raw file bytes.

    Returns a dict with a stable top-level shape (see module docstring).
    Never raises on malformed/corrupt/empty input — extraction failures are
    reported inside the returned structure's ``warnings`` list.
    """
    started = time.perf_counter()
    filename = filename or "file"
    ext = _extension(filename)
    resolved_mime = mime_type or SUPPORTED_TYPES.get(ext) or "application/octet-stream"
    supported = ext in SUPPORTED_TYPES
    size = len(data)

    logger.info("Upload received: filename=%s ext=%s mime=%s size=%d bytes",
                filename, ext, resolved_mime, size)

    warnings: list[str] = []

    # ── Hashes (always computed) ──────────────────────────────────────────────
    hashes = _compute_hashes(data, ext)

    # ── File category (always populated) ──────────────────────────────────────
    file_cat = {
        "filename": filename,
        "mime_type": resolved_mime,
        "extension": ext or None,
        "size": size,
        "sha256": hashes.get("sha256"),
    }

    if size == 0:
        warnings.append("Empty upload: no metadata to extract.")

    # ── Select extractor ──────────────────────────────────────────────────────
    use_exiftool = exiftool_available()
    extractor = "exiftool" if use_exiftool else "python-fallback"
    logger.info("Extractor selected: %s (exiftool_available=%s, supported=%s)",
                extractor, use_exiftool, supported)

    # Structured sub-blocks populated by the extractors below.
    blocks: Dict[str, Dict[str, Any]] = {
        "exif": {}, "iptc": {}, "xmp": {}, "audio_tags": {},
    }

    raw: Dict[str, Any] = {}
    if size > 0:
        if use_exiftool:
            raw, exif_warn = _run_exiftool(data, ext)
            warnings.extend(exif_warn)
            if not raw:
                logger.info("ExifTool returned no data; using python fallback.")
                extractor = "python-fallback"
                raw = _python_raw(data, ext, resolved_mime, warnings, blocks)
            else:
                _partition_exiftool_groups(raw, blocks)
        else:
            raw = _python_raw(data, ext, resolved_mime, warnings, blocks)

    # ── Normalize into categories ──────────────────────────────────────────────
    lower = {str(k).lower(): v for k, v in raw.items()}
    gps = _normalize_gps(lower)
    result = {
        "extractor": extractor,
        "exiftool_available": use_exiftool,
        "supported": supported,
        "file": file_cat,
        "technical": _normalize_technical(lower, data, ext, resolved_mime),
        "codec": _normalize_codec(lower, ext, resolved_mime),
        "container": _normalize_container(lower, ext, resolved_mime),
        "timestamps": _normalize_timestamps(lower),
        "camera": _normalize_camera(lower),
        "gps": gps,
        # Backward-compatible alias; existing consumers/tests read `location`.
        "location": gps,
        "copyright": _normalize_copyright(lower),
        "software": _normalize_software(lower),
        "audio_tags": _normalize_audio_tags(blocks["audio_tags"], lower, ext, resolved_mime),
        "exif": blocks["exif"],
        "iptc": blocks["iptc"],
        "xmp": blocks["xmp"],
        "hashes": hashes,
        "raw_metadata": raw,
        "warnings": warnings,
    }

    duration_ms = round((time.perf_counter() - started) * 1000, 2)
    result["duration_ms"] = duration_ms

    if raw or size == 0 or extractor == "exiftool":
        logger.info("Extraction success: filename=%s extractor=%s duration=%.2fms "
                    "raw_fields=%d", filename, extractor, duration_ms, len(raw))
    else:
        reason = "; ".join(warnings) or "no metadata extracted"
        logger.warning("Extraction produced no metadata: filename=%s reason=%s "
                        "duration=%.2fms", filename, reason, duration_ms)

    return result


# ── Hashing ────────────────────────────────────────────────────────────────────

def _compute_hashes(data: bytes, ext: str) -> Dict[str, Any]:
    h: Dict[str, Any] = {
        "sha256": hashlib.sha256(data).hexdigest(),
        "md5": hashlib.md5(data).hexdigest(),
        "perceptual_hash": None,
    }
    if ext in IMAGE_EXTS:
        try:
            import imagehash
            from PIL import Image
            h["perceptual_hash"] = str(imagehash.phash(Image.open(io.BytesIO(data))))
        except Exception:
            h["perceptual_hash"] = None
    return h


# ── ExifTool path ────────────────────────────────────────────────────────────

def _run_exiftool(data: bytes, ext: str) -> tuple[Dict[str, Any], list[str]]:
    """Run exiftool -json against the bytes written to a temp file."""
    warnings: list[str] = []
    tmp_path = None
    try:
        suffix = f".{ext}" if ext else ""
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
            tmp.write(data)
            tmp_path = tmp.name
        proc = subprocess.run(
            ["exiftool", "-json", "-G", "-n", "-api", "largefilesupport=1", tmp_path],
            capture_output=True, timeout=30,
        )
        if proc.returncode != 0 and not proc.stdout:
            warnings.append(f"ExifTool error: {proc.stderr.decode('utf-8', 'ignore')[:200]}")
            return {}, warnings
        parsed = json.loads(proc.stdout.decode("utf-8", "ignore") or "[]")
        if isinstance(parsed, list) and parsed:
            raw = parsed[0]
            raw.pop("SourceFile", None)
            return raw, warnings
        return {}, warnings
    except Exception as e:  # never fail the upload
        warnings.append(f"ExifTool exception: {type(e).__name__}: {str(e)[:150]}")
        return {}, warnings
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass


def _partition_exiftool_groups(raw: Dict[str, Any], blocks: Dict[str, Dict[str, Any]]) -> None:
    """Split ExifTool ``-G`` output (keys look like ``EXIF:Make``) into the
    normalized exif / iptc / xmp / audio_tags blocks. Keys without a group
    prefix are ignored here (they remain available in ``raw_metadata``)."""
    for key, value in raw.items():
        if ":" not in str(key):
            continue
        group, _, tag = str(key).partition(":")
        gu = group.upper()
        if gu in _EXIF_GROUPS:
            blocks["exif"][tag] = value
        elif gu in _IPTC_GROUPS:
            blocks["iptc"][tag] = value
        elif gu in _XMP_GROUPS or gu.startswith("XMP"):
            blocks["xmp"][tag] = value
        elif gu in _AUDIO_GROUPS:
            blocks["audio_tags"][tag] = value


# ── Pure-Python fallback path ─────────────────────────────────────────────────

def _python_raw(data: bytes, ext: str, mime: str, warnings: list[str],
                blocks: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """Fallback extraction using libraries already in the repo."""
    raw: Dict[str, Any] = {}
    try:
        if ext in IMAGE_EXTS or mime.startswith("image/"):
            raw.update(_py_image(data, warnings, blocks))
        elif ext in AUDIO_EXTS or mime.startswith("audio/"):
            raw.update(_py_audio(data, warnings, blocks))
        elif ext == "pdf" or mime == "application/pdf":
            raw.update(_py_pdf(data, warnings, blocks))
        elif ext in VIDEO_EXTS or mime.startswith("video/"):
            warnings.append(
                "Video metadata requires ExifTool; pure-Python fallback provides "
                "container-level info only.")
            raw.update(_py_container_basic(data, ext))
        elif ext in {"docx", "pptx", "xlsx"}:
            warnings.append(
                "Office document metadata requires ExifTool (or python-docx/"
                "openpyxl, not installed); returning file-level info only.")
            raw.update(_py_container_basic(data, ext))
        else:
            warnings.append(f"Unsupported type '{ext or mime}': file-level metadata only.")
    except Exception as e:
        warnings.append(f"Fallback extraction error: {type(e).__name__}: {str(e)[:150]}")
    return raw


def _py_image(data: bytes, warnings: list[str],
              blocks: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    img = None
    # Pillow: format / size / mode
    try:
        from PIL import Image
        img = Image.open(io.BytesIO(data))
        out["ImageWidth"] = img.width
        out["ImageHeight"] = img.height
        out["Format"] = img.format
        out["ColorMode"] = img.mode
    except Exception as e:
        warnings.append(f"Pillow could not open image: {type(e).__name__}")
    # EXIF via exifread (raw + structured exif/gps block)
    try:
        import exifread
        tags = exifread.process_file(io.BytesIO(data), details=False)
        for k, v in tags.items():
            ks = str(k)
            out[ks] = str(v)
            grp = ks.split(" ")[0].upper()
            if grp in ("IMAGE", "EXIF", "THUMBNAIL") or ks.upper().startswith("EXIF"):
                blocks["exif"][ks] = str(v)
    except Exception:
        pass
    # IPTC via Pillow (best-effort; only JPEG/TIFF carry IPTC)
    if img is not None:
        try:
            from PIL import IptcImagePlugin
            iptc = IptcImagePlugin.getiptcinfo(img)
            if iptc:
                for key, val in iptc.items():
                    try:
                        sval = val.decode("utf-8", "ignore") if isinstance(val, bytes) else (
                            [x.decode("utf-8", "ignore") if isinstance(x, bytes) else x for x in val]
                            if isinstance(val, (list, tuple)) else val)
                    except Exception:
                        sval = str(val)
                    blocks["iptc"][f"{key[0]}:{key[1]}"] = sval
        except Exception:
            pass
        # XMP via Pillow (>=8.2). Needs defusedxml; if absent Pillow warns and
        # returns {} — suppress the warning and degrade gracefully.
        try:
            import warnings as _w
            with _w.catch_warnings():
                _w.simplefilter("ignore")
                xmp = img.getxmp() if hasattr(img, "getxmp") else {}
            if xmp:
                blocks["xmp"].update(_flatten_xmp(xmp))
        except Exception:
            pass
    return out


def _py_audio(data: bytes, warnings: list[str],
              blocks: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    try:
        import mutagen
        f = mutagen.File(io.BytesIO(data))
        if f is not None:
            info = getattr(f, "info", None)
            if info is not None:
                for attr in ("length", "bitrate", "sample_rate", "channels", "bits_per_sample"):
                    if hasattr(info, attr):
                        out[attr] = getattr(info, attr)
                if hasattr(info, "codec"):
                    out["codec"] = getattr(info, "codec")
            if getattr(f, "tags", None):
                for k, v in f.tags.items():
                    out[str(k)] = str(v)
                    blocks["audio_tags"][str(k)] = str(v)
        else:
            warnings.append("mutagen could not parse audio stream.")
    except Exception as e:
        warnings.append(f"mutagen error: {type(e).__name__}")
    return out


def _py_pdf(data: bytes, warnings: list[str],
            blocks: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    try:
        from pypdf import PdfReader
        reader = PdfReader(io.BytesIO(data))
        out["PageCount"] = len(reader.pages)
        info = reader.metadata or {}
        for k, v in info.items():
            out[str(k)] = str(v)
        # XMP metadata packet, when present.
        try:
            xmp = reader.xmp_metadata
            if xmp is not None:
                for attr in ("dc_title", "dc_creator", "dc_description", "dc_subject",
                             "dc_publisher", "dc_rights", "xmp_create_date",
                             "xmp_modify_date", "xmp_creator_tool", "pdf_producer",
                             "pdf_keywords"):
                    try:
                        val = getattr(xmp, attr, None)
                    except Exception:
                        val = None
                    if val:
                        blocks["xmp"][attr] = str(val)
        except Exception:
            pass
    except Exception as e:
        warnings.append(f"pypdf error: {type(e).__name__}")
    return out


def _py_container_basic(data: bytes, ext: str) -> Dict[str, Any]:
    return {"Container": ext.upper() if ext else None, "ByteSize": len(data)}


def _flatten_xmp(xmp: Any, prefix: str = "") -> Dict[str, Any]:
    """Flatten Pillow's nested getxmp() dict into flat 'a.b.c' -> value pairs."""
    flat: Dict[str, Any] = {}
    if isinstance(xmp, dict):
        for k, v in xmp.items():
            key = f"{prefix}.{k}" if prefix else str(k)
            if isinstance(v, (dict, list)):
                flat.update(_flatten_xmp(v, key))
            else:
                flat[key] = v
    elif isinstance(xmp, list):
        for i, v in enumerate(xmp):
            key = f"{prefix}[{i}]"
            if isinstance(v, (dict, list)):
                flat.update(_flatten_xmp(v, key))
            else:
                flat[key] = v
    else:
        if prefix:
            flat[prefix] = xmp
    return flat


# ── Normalization helpers ──────────────────────────────────────────────────────

def _first(lower: Dict[str, Any], *keys: str) -> Any:
    """Return the first present value among candidate keys (case-insensitive,
    keys may be given as bare tag names or 'group:tag')."""
    for key in keys:
        k = key.lower()
        if k in lower and lower[k] not in (None, ""):
            return lower[k]
        # match keys that end with ':tag' (ExifTool -G group prefix)
        for lk, lv in lower.items():
            if lk.split(":")[-1] == k and lv not in (None, ""):
                return lv
    return None


def _normalize_technical(lower, data, ext, mime) -> Dict[str, Any]:
    width = _first(lower, "imagewidth", "exifimagewidth", "width")
    height = _first(lower, "imageheight", "exifimageheight", "height")
    resolution = None
    if width and height:
        resolution = f"{width}x{height}"
    return {
        "format": _first(lower, "format", "filetype", "fileformat") or (ext.upper() if ext else None),
        "codec": _first(lower, "compression", "audiocodec", "videocodec", "codec"),
        "container": _first(lower, "container", "majorbrand", "filetypeextension"),
        "duration": _first(lower, "duration", "length", "playduration"),
        "bitrate": _first(lower, "bitrate", "audiobitrate", "avgbitrate"),
        "resolution": resolution,
        "sample_rate": _first(lower, "sample_rate", "samplerate", "audiosamplerate"),
        "channels": _first(lower, "channels", "audiochannels", "channelmode"),
    }


def _normalize_codec(lower, ext, mime) -> Dict[str, Any]:
    return {
        "audio": _first(lower, "audiocodec", "codec", "audioformat", "compression"
                        ) if (ext in AUDIO_EXTS or mime.startswith("audio/")) else _first(lower, "audiocodec"),
        "video": _first(lower, "videocodec", "compressorid", "compression"
                        ) if (ext in VIDEO_EXTS or mime.startswith("video/")) else None,
        "compression": _first(lower, "compression"),
    }


def _normalize_container(lower, ext, mime) -> Dict[str, Any]:
    return {
        "format": _first(lower, "filetype", "format", "fileformat") or (ext.upper() if ext else None),
        "major_brand": _first(lower, "majorbrand"),
        "mime_type": _first(lower, "mimetype") or mime,
        "extension": _first(lower, "filetypeextension") or (ext or None),
    }


def _normalize_timestamps(lower) -> Dict[str, Any]:
    # NOTE: exifread emits space-separated group keys ("EXIF DateTimeOriginal",
    # "Image DateTime"); the ExifTool -G path emits colon-separated keys
    # ("EXIF:DateTimeOriginal"). The space-form candidates below are required so
    # the pure-Python (exifread) fallback populates timestamps — otherwise these
    # values are present in raw metadata but silently lost during normalization.
    # This mirrors the existing "image make" precedent in _normalize_camera.
    return {
        "created": _first(lower, "createdate", "datetimeoriginal",
                          "exif datetimeoriginal", "creationdate", "/creationdate"),
        "modified": _first(lower, "modifydate", "image datetime",
                           "filemodifydate", "/moddate"),
        "encoded": _first(lower, "encodetime", "mediacreatedate"),
        "digitized": _first(lower, "datetimedigitized", "exif datetimedigitized",
                            "digitalcreationdatetime"),
        "timezone": _first(lower, "timezone", "offsettime", "offsettimeoriginal"),
    }


def _normalize_camera(lower) -> Dict[str, Any]:
    return {
        "make": _first(lower, "make", "image make", "cameramake"),
        "model": _first(lower, "model", "image model", "cameramodel"),
        "lens": _first(lower, "lensmodel", "lens", "lensinfo"),
        "iso": _first(lower, "iso", "isospeed", "exif isospeedratings"),
        "aperture": _first(lower, "aperture", "fnumber", "exif fnumber"),
        "shutter": _first(lower, "shutterspeed", "exposuretime", "exif exposuretime"),
        "focal_length": _first(lower, "focallength", "exif focallength"),
    }


def _normalize_gps(lower) -> Dict[str, Any]:
    lat = _first(lower, "gpslatitude", "gps gpslatitude")
    lon = _first(lower, "gpslongitude", "gps gpslongitude")
    alt = _first(lower, "gpsaltitude", "gps gpsaltitude")
    coords = None
    if lat is not None and lon is not None:
        coords = {"latitude": lat, "longitude": lon}
    gps_pos = _first(lower, "gpsposition")
    return {
        "gps": gps_pos if gps_pos is not None else (coords is not None),
        "latitude": lat,
        "longitude": lon,
        "altitude": alt,
        "country": _first(lower, "country", "countrycode", "gpscountry"),
        "city": _first(lower, "city", "sub-location"),
        "coordinates": coords,
    }


def _normalize_copyright(lower) -> Dict[str, Any]:
    return {
        "creator": _first(lower, "creator", "artist", "author", "/author", "by-line"),
        "copyright": _first(lower, "copyright", "rights", "copyrightnotice"),
        "license": _first(lower, "license", "usageterms", "webstatement"),
        "publisher": _first(lower, "publisher", "credit", "source"),
    }


def _normalize_software(lower) -> Dict[str, Any]:
    return {
        "editing_software": _first(lower, "software", "image software", "creatortool", "/creator", "processingsoftware"),
        "encoder": _first(lower, "encoder", "encodedby", "encodingtool"),
        "export_application": _first(lower, "applicationname", "producer", "/producer", "hostcomputer"),
    }


def _normalize_audio_tags(audio_block: Dict[str, Any], lower, ext, mime) -> Dict[str, Any]:
    """Produce friendly audio tag names plus the raw tag block."""
    friendly: Dict[str, Any] = {
        "title": None, "artist": None, "album": None, "genre": None,
        "year": None, "track": None, "comment": None,
        "album_artist": None, "composer": None,
    }
    for key, val in (audio_block or {}).items():
        base = str(key).split(":")[0].lower()
        # ID3 frames sometimes look like "COMM::eng"; take leading alpha token.
        base = "".join(ch for ch in base if ch.isalpha() or ch.isdigit())
        friendly_name = _AUDIO_TAG_MAP.get(base)
        if friendly_name and friendly.get(friendly_name) in (None, ""):
            friendly[friendly_name] = val
    return {**friendly, "raw": audio_block or {}}


def _extension(filename: str) -> str:
    _, dot, ext = (filename or "").rpartition(".")
    return ext.lower() if dot else ""
