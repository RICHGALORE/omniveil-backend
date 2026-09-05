import asyncio

from app.services import hive_detection, synthetic_detection
from app.services.omnispectra import build_omnispectra_report


def test_hive_media_reads_named_class_without_array_position(monkeypatch):
    async def fake_submit(**kwargs):
        return {
            "status": [
                {
                    "response": {
                        "output": [
                            {
                                "classes": [
                                    {"class": "not_ai_generated", "score": 0.17},
                                    {"class": "ai_generated", "score": 0.83},
                                ]
                            }
                        ]
                    }
                }
            ]
        }

    monkeypatch.setattr(hive_detection, "_submit", fake_submit)
    result = asyncio.run(
        hive_detection.detect_generated_media(
            b"image",
            api_key="test-key",
            filename="asset.png",
            mime_type="image/png",
        )
    )
    assert result is not None
    assert result["provider"] == "hive"
    assert result["model"] == "ai_generated_media"
    assert result["probability"] == 0.83


def test_hive_audio_uses_max_reported_chunk_probability(monkeypatch):
    async def fake_submit(**kwargs):
        return {
            "status": [
                {
                    "response": {
                        "output": [
                            {
                                "start_time": 0,
                                "classes": [
                                    {"class": "ai_generated", "score": 0.18},
                                    {"class": "not_ai_generated", "score": 0.82},
                                ],
                            },
                            {
                                "start_time": 10,
                                "classes": [
                                    {"class": "ai_generated", "score": 0.72},
                                    {"class": "not_ai_generated", "score": 0.28},
                                ],
                            },
                        ]
                    }
                }
            ]
        }

    monkeypatch.setattr(hive_detection, "_submit", fake_submit)
    result = asyncio.run(
        hive_detection.detect_generated_audio(
            b"audio",
            api_key="test-key",
            filename="clip.wav",
            mime_type="audio/wav",
        )
    )
    assert result is not None
    assert result["probability"] == 0.72
    assert result["details"]["aggregation"] == "max_reported_chunk_probability"
    assert result["details"]["segment_count"] == 2


def test_hive_music_keeps_music_cover_and_attribution_separate(monkeypatch):
    async def fake_submit(**kwargs):
        return {
            "status": [
                {
                    "response": {
                        "output": [
                            {
                                "classes": [
                                    {"class": "ai_generated_music", "score": 0.81},
                                    {"class": "not_ai_generated_music", "score": 0.19},
                                    {"class": "suno", "score": 0.64},
                                    {"class": "udio", "score": 0.21},
                                    {"class": "ai_generated_music_cover", "score": 0.31},
                                    {"class": "not_ai_generated_music_cover", "score": 0.69},
                                ]
                            }
                        ]
                    }
                }
            ]
        }

    monkeypatch.setattr(hive_detection, "_submit", fake_submit)
    results = asyncio.run(
        hive_detection.detect_generated_music(
            b"music",
            api_key="music-key",
            filename="song.wav",
            mime_type="audio/wav",
        )
    )
    by_signal = {item["signal"]: item for item in results}
    assert by_signal["synthetic_music_probability"]["probability"] == 0.81
    assert by_signal["synthetic_music_cover_probability"]["probability"] == 0.31
    assert (
        by_signal["synthetic_music_probability"]["details"]["top_generator_attribution"]["class"]
        == "suno"
    )


def test_no_hive_key_short_circuits_before_network(monkeypatch):
    class NetworkMustNotStart:
        def __init__(self, *args, **kwargs):
            raise AssertionError("Hive HTTP client must not start without an API key")

    monkeypatch.setattr(hive_detection.httpx, "AsyncClient", NetworkMustNotStart)

    direct = asyncio.run(
        hive_detection._submit(
            api_key="",
            data=b"image",
            filename="asset.png",
            mime_type="image/png",
        )
    )
    media = asyncio.run(
        hive_detection.detect_generated_media(
            b"image",
            api_key="",
            filename="asset.png",
            mime_type="image/png",
        )
    )
    assert direct is None
    assert media is None


def test_orchestrator_preserves_sightengine_and_hive_as_independent_observations(monkeypatch):
    async def fake_sightengine(data, mime_type):
        return 0.22

    async def fake_hive(data, *, api_key, filename, mime_type):
        return {
            "provider": "hive",
            "model": "ai_generated_media",
            "signal": "synthetic_media_probability",
            "probability": 0.88,
            "status": "available",
            "details": {},
        }

    monkeypatch.setattr(
        synthetic_detection.sightengine_compat,
        "detect_ai_image",
        fake_sightengine,
    )
    monkeypatch.setattr(synthetic_detection, "hive_detect_media", fake_hive)
    monkeypatch.setattr(synthetic_detection.settings, "hive_media_api_key", "hive-key")
    monkeypatch.setattr(synthetic_detection.settings, "hive_api_key", "")

    observations = asyncio.run(
        synthetic_detection.run_synthetic_detectors(
            b"image",
            mime_type="image/png",
            filename="asset.png",
        )
    )
    assert [(item["provider"], item["probability"]) for item in observations] == [
        ("sightengine", 0.22),
        ("hive", 0.88),
    ]
    assert synthetic_detection.sightengine_legacy_score(observations) == 0.22


def test_omnispectra_does_not_average_provider_scores():
    report = build_omnispectra_report(
        filename="asset.png",
        ai_detection_score=0.20,
        detector_provider="sightengine",
        detector_model="genai",
        detector_observations=[
            {
                "provider": "sightengine",
                "model": "genai",
                "signal": "synthetic_media_probability",
                "probability": 0.20,
            },
            {
                "provider": "hive",
                "model": "ai_generated_media",
                "signal": "synthetic_media_probability",
                "probability": 0.88,
            },
        ],
        anomaly={"anomaly_score": 0, "flags": [], "anomaly_summary": "No anomalies."},
    )
    summary = report["signals"]["synthetic_detector_summary"]
    assert summary["provider_count"] == 2
    assert summary["consensus_score"] is None
    assert report["signals"]["synthetic_detection"]["provider"] == "sightengine"
    assert report["verdict"] == "high_review_priority"
