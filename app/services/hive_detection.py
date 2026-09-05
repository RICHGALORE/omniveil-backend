"""Hive V2 synthetic-media detector adapter.

The adapter keeps third-party model evidence provider-specific. It never logs
API keys or raw Hive responses and it never turns a detector score into an
authenticity/authorship determination.

Hive uses project/model API keys. Omni Veil therefore supports separate keys
for AI-generated visual media, general AI-generated audio, and AI-generated
music. The legacy HIVE_API_KEY setting is accepted only as a visual-media
fallback so one ambiguous key is not silently reused across unrelated models.
"""
from __future__ import annotations

import logging
from typing import Any, Iterable

import httpx


logger = logging.getLogger("omniveil.hive_detection")

HIVE_SYNC_URL = "https://api.thehive.ai/api/v2/task/sync"
HIVE_PROVIDER = "hive"

MUSIC_ATTRIBUTION_CLASSES = {
    "duobao",
    "google",
    "heartmula",
    "loudly",
    "minimax",
    "mubert",
    "mureka",
    "musicgen",
    "riffusion",
    "stable_audio_open",
    "suno",
    "udio",
    "yue",
    "ace_step",
}


def _clamp_probability(value: Any) -> float | None:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return max(0.0, min(1.0, number))


def _walk_class_rows(value: Any) -> Iterable[dict[str, Any]]:
    """Yield any nested Hive class rows without relying on array position."""
    if isinstance(value, dict):
        if "class" in value and "score" in value:
            yield value
        for child in value.values():
            yield from _walk_class_rows(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_class_rows(child)


def _walk_outputs(value: Any) -> Iterable[dict[str, Any]]:
    if isinstance(value, dict):
        output = value.get("output")
        if isinstance(output, list):
            for row in output:
                if isinstance(row, dict):
                    yield row
        for child in value.values():
            yield from _walk_outputs(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_outputs(child)


def _max_class(payload: dict[str, Any], class_name: str) -> float | None:
    scores = [
        score
        for row in _walk_class_rows(payload)
        if str(row.get("class") or "").strip().lower() == class_name
        if (score := _clamp_probability(row.get("score"))) is not None
    ]
    return max(scores) if scores else None


def _segment_count(payload: dict[str, Any]) -> int:
    outputs = list(_walk_outputs(payload))
    return len(outputs)


def _top_music_attribution(payload: dict[str, Any]) -> dict[str, Any] | None:
    best_name = None
    best_score = -1.0
    for row in _walk_class_rows(payload):
        name = str(row.get("class") or "").strip().lower()
        if name not in MUSIC_ATTRIBUTION_CLASSES:
            continue
        score = _clamp_probability(row.get("score"))
        if score is not None and score > best_score:
            best_name = name
            best_score = score
    if best_name is None:
        return None
    return {"class": best_name, "score": round(best_score, 6)}


async def _submit(
    *,
    api_key: str,
    data: bytes,
    filename: str,
    mime_type: str,
    timeout: float = 60.0,
) -> dict[str, Any] | None:
    if not api_key:
        return None

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(
                HIVE_SYNC_URL,
                headers={
                    "authorization": f"token {api_key}",
                    "accept": "application/json",
                },
                files={
                    "media": (
                        filename or "asset.bin",
                        data,
                        mime_type or "application/octet-stream",
                    )
                },
            )
        if response.status_code != 200:
            logger.warning("Hive detection returned status=%s", response.status_code)
            return None
        payload = response.json()
        if not isinstance(payload, dict):
            logger.warning("Hive detection returned non-object JSON")
            return None
        return payload
    except (httpx.HTTPError, ValueError) as exc:
        logger.warning("Hive detection failed: %s", type(exc).__name__)
        return None


async def detect_generated_media(
    data: bytes,
    *,
    api_key: str,
    filename: str,
    mime_type: str,
) -> dict[str, Any] | None:
    """Return Hive visual-media evidence for an image/video when configured."""
    payload = await _submit(
        api_key=api_key,
        data=data,
        filename=filename,
        mime_type=mime_type,
    )
    if not payload:
        return None
    probability = _max_class(payload, "ai_generated")
    if probability is None:
        return None
    return {
        "provider": HIVE_PROVIDER,
        "model": "ai_generated_media",
        "signal": "synthetic_media_probability",
        "probability": probability,
        "status": "available",
        "details": {
            "segment_count": _segment_count(payload),
            "interpretation": "probabilistic_signal_not_determination",
        },
    }


async def detect_generated_audio(
    data: bytes,
    *,
    api_key: str,
    filename: str,
    mime_type: str,
) -> dict[str, Any] | None:
    """Return the maximum Hive ai_generated score across reported audio chunks."""
    payload = await _submit(
        api_key=api_key,
        data=data,
        filename=filename,
        mime_type=mime_type,
    )
    if not payload:
        return None
    probability = _max_class(payload, "ai_generated")
    if probability is None:
        return None
    return {
        "provider": HIVE_PROVIDER,
        "model": "ai_generated_audio",
        "signal": "synthetic_audio_probability",
        "probability": probability,
        "status": "available",
        "details": {
            "aggregation": "max_reported_chunk_probability",
            "segment_count": _segment_count(payload),
            "interpretation": "probabilistic_signal_not_determination",
        },
    }


async def detect_generated_music(
    data: bytes,
    *,
    api_key: str,
    filename: str,
    mime_type: str,
) -> list[dict[str, Any]]:
    """Return Hive music-generation and vocal-cover observations separately."""
    payload = await _submit(
        api_key=api_key,
        data=data,
        filename=filename,
        mime_type=mime_type,
    )
    if not payload:
        return []

    observations: list[dict[str, Any]] = []
    common_details = {
        "aggregation": "max_reported_chunk_probability",
        "segment_count": _segment_count(payload),
        "interpretation": "probabilistic_signal_not_determination",
    }
    attribution = _top_music_attribution(payload)
    if attribution:
        common_details["top_generator_attribution"] = attribution

    generated_music = _max_class(payload, "ai_generated_music")
    if generated_music is not None:
        observations.append(
            {
                "provider": HIVE_PROVIDER,
                "model": "ai_generated_music",
                "signal": "synthetic_music_probability",
                "probability": generated_music,
                "status": "available",
                "details": dict(common_details),
            }
        )

    generated_cover = _max_class(payload, "ai_generated_music_cover")
    if generated_cover is not None:
        observations.append(
            {
                "provider": HIVE_PROVIDER,
                "model": "ai_generated_music_cover",
                "signal": "synthetic_music_cover_probability",
                "probability": generated_cover,
                "status": "available",
                "details": dict(common_details),
            }
        )

    return observations
