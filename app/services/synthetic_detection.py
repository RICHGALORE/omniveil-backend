"""Synthetic-media detector orchestration.

Provider observations remain independent. Omni Veil does not average detector
scores into an artificial consensus or treat any detector as an authorship or
authenticity oracle.
"""
from __future__ import annotations

import logging
from typing import Any

from app.core.config import settings
from app.services.hive_detection import (
    detect_generated_audio as hive_detect_audio,
    detect_generated_media as hive_detect_media,
    detect_generated_music as hive_detect_music,
)
from app.utils import hive as sightengine_compat


logger = logging.getLogger("omniveil.synthetic_detection")


def _observation(
    *,
    provider: str,
    model: str,
    signal: str,
    probability: float | None,
    details: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    if probability is None:
        return None
    return {
        "provider": provider,
        "model": model,
        "signal": signal,
        "probability": max(0.0, min(1.0, float(probability))),
        "status": "available",
        "details": details or {"interpretation": "probabilistic_signal_not_determination"},
    }


async def run_synthetic_detectors(
    data: bytes,
    *,
    mime_type: str,
    filename: str | None = None,
) -> list[dict[str, Any]]:
    """Run configured detectors and return provider-separated observations.

    Sightengine remains the backward-compatible Provider A. Hive is Provider B
    and may contribute visual, general-audio, and music-specific observations
    depending on which project keys are configured.
    """
    filename = filename or "asset.bin"
    observations: list[dict[str, Any]] = []

    # Provider A — preserve the existing Sightengine behavior and semantics.
    sightengine_score = None
    try:
        if mime_type.startswith("image/"):
            sightengine_score = await sightengine_compat.detect_ai_image(data, mime_type)
        elif mime_type.startswith("audio/"):
            sightengine_score = await sightengine_compat.detect_ai_audio(data)
    except Exception as exc:  # Provider failure must not fail ingest/scan.
        logger.warning("Sightengine detector failed: %s", type(exc).__name__)

    sightengine_observation = _observation(
        provider="sightengine",
        model="genai",
        signal=(
            "synthetic_audio_probability"
            if mime_type.startswith("audio/")
            else "synthetic_media_probability"
        ),
        probability=sightengine_score,
    )
    if sightengine_observation:
        observations.append(sightengine_observation)

    # Provider B — Hive project keys are intentionally separated by model family.
    try:
        if mime_type.startswith(("image/", "video/")):
            media_key = settings.hive_media_api_key or settings.hive_api_key
            if media_key:
                hive_media = await hive_detect_media(
                    data,
                    api_key=media_key,
                    filename=filename,
                    mime_type=mime_type,
                )
                if hive_media:
                    observations.append(hive_media)

        if mime_type.startswith("audio/"):
            if settings.hive_audio_api_key:
                hive_audio = await hive_detect_audio(
                    data,
                    api_key=settings.hive_audio_api_key,
                    filename=filename,
                    mime_type=mime_type,
                )
                if hive_audio:
                    observations.append(hive_audio)

            if settings.hive_music_api_key:
                observations.extend(
                    await hive_detect_music(
                        data,
                        api_key=settings.hive_music_api_key,
                        filename=filename,
                        mime_type=mime_type,
                    )
                )
    except Exception as exc:  # Independent provider failure remains non-fatal.
        logger.warning("Hive detector failed: %s", type(exc).__name__)

    return observations


def sightengine_legacy_score(observations: list[dict[str, Any]]) -> float | None:
    """Extract the historical Provider-A score without changing trust semantics."""
    for observation in observations:
        if (
            observation.get("provider") == "sightengine"
            and observation.get("model") == "genai"
        ):
            try:
                return float(observation.get("probability"))
            except (TypeError, ValueError):
                return None
    return None
