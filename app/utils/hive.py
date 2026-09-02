"""Legacy synthetic-detection compatibility module.

The filename predates the current provider integration. The active image/audio
implementation below calls Sightengine's `genai` model. Keep the public helper
names for existing ingest/tests while exposing truthful provider metadata to
OmniSpectra and avoiding raw third-party response logging.
"""
import logging
from typing import Optional

import httpx


logger = logging.getLogger("omniveil.synthetic_detection")

HIVE_API_KEY = str()
SIGHTENGINE_USER = str()
SIGHTENGINE_SECRET = str()

DETECTOR_PROVIDER = "sightengine"
DETECTOR_MODEL = "genai"


def set_key(key):
    global HIVE_API_KEY
    HIVE_API_KEY = key


def set_sightengine(user, secret):
    global SIGHTENGINE_USER, SIGHTENGINE_SECRET
    SIGHTENGINE_USER = user
    SIGHTENGINE_SECRET = secret


def detector_metadata() -> dict:
    """Describe the currently implemented detector without exposing secrets."""
    return {
        "provider": DETECTOR_PROVIDER,
        "model": DETECTOR_MODEL,
        "configured": bool(SIGHTENGINE_USER and SIGHTENGINE_SECRET),
    }


async def detect_ai_image(image_bytes, mime_type="image/jpeg") -> Optional[float]:
    if not SIGHTENGINE_USER or not SIGHTENGINE_SECRET:
        return None
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            resp = await client.post(
                "https://api.sightengine.com/1.0/check.json",
                data={
                    "models": DETECTOR_MODEL,
                    "api_user": SIGHTENGINE_USER,
                    "api_secret": SIGHTENGINE_SECRET,
                },
                files={"media": ("image.jpg", image_bytes, mime_type or "image/jpeg")},
            )
            if resp.status_code != 200:
                logger.warning(
                    "Sightengine image detection returned status=%s",
                    resp.status_code,
                )
                return None
            data = resp.json()
            return float(data.get("type", {}).get("ai_generated", 0) or 0)
    except Exception as exc:
        logger.warning("Sightengine image detection failed: %s", type(exc).__name__)
        return None


async def detect_ai_audio(audio_bytes) -> Optional[float]:
    if not SIGHTENGINE_USER or not SIGHTENGINE_SECRET:
        return None
    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(
                "https://api.sightengine.com/1.0/audio/check.json",
                data={
                    "models": DETECTOR_MODEL,
                    "api_user": SIGHTENGINE_USER,
                    "api_secret": SIGHTENGINE_SECRET,
                },
                files={"media": ("audio.mp3", audio_bytes, "audio/mpeg")},
            )
            if resp.status_code != 200:
                logger.warning(
                    "Sightengine audio detection returned status=%s",
                    resp.status_code,
                )
                return None
            data = resp.json()
            return float(data.get("type", {}).get("ai_generated", 0) or 0)
    except Exception as exc:
        logger.warning("Sightengine audio detection failed: %s", type(exc).__name__)
        return None
