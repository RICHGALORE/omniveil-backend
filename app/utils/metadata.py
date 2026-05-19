import io
from typing import Any

def extract_metadata(data: bytes, mime_type: str) -> dict[str, Any]:
    meta: dict[str, Any] = {}
    try:
        if mime_type.startswith("image/"):
            meta["exif"] = _extract_exif(data)
        elif mime_type == "application/pdf":
            meta["pdf"] = _extract_pdf(data)
        elif mime_type.startswith("audio/"):
            meta["audio"] = _extract_audio(data)
    except Exception as e:
        meta["error"] = str(e)
    return meta

def _extract_exif(data: bytes) -> dict[str, Any]:
    try:
        import exifread
        tags = exifread.process_file(io.BytesIO(data), details=False)
        return {str(k): str(v) for k, v in tags.items()}
    except Exception:
        return {}

def _extract_pdf(data: bytes) -> dict[str, Any]:
    try:
        from pypdf import PdfReader
        reader = PdfReader(io.BytesIO(data))
        info = reader.metadata or {}
        return {str(k): str(v) for k, v in info.items()}
    except Exception:
        return {}

def _extract_audio(data: bytes) -> dict[str, Any]:
    try:
        import mutagen
        f = mutagen.File(io.BytesIO(data))
        if f:
            return {str(k): str(v) for k, v in f.tags.items() if f.tags}
        return {}
    except Exception:
        return {}
