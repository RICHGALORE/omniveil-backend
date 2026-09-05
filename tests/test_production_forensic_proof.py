import pytest

from scripts.production_forensic_proof import (
    ProofFailure,
    _assert_evidence_graph,
    _assert_expected_providers,
    _providers,
)


def _report(*providers):
    observations = []
    for index, provider in enumerate(providers):
        observations.append(
            {
                "provider": provider,
                "model": "model-a",
                "signal": "synthetic_media_probability",
                "probability": 0.2 + (index * 0.2),
                "status": "available",
                "details": {},
            }
        )
    return {
        "signals": {
            "synthetic_detector_summary": {
                "providers": list(providers),
                "provider_count": len(set(providers)),
                "consensus_score": None,
            },
            "synthetic_detectors": observations,
        }
    }


def test_expected_provider_parser_normalizes_and_deduplicates():
    assert _providers(" SightEngine, hive, HIVE ,") == {"sightengine", "hive"}


def test_forensic_proof_requires_independent_provider_rows_without_consensus():
    providers, observations = _assert_expected_providers(
        _report("sightengine", "hive"),
        {"sightengine", "hive"},
    )
    assert providers == {"sightengine", "hive"}
    assert len(observations) == 2


def test_forensic_proof_fails_when_expected_provider_is_missing():
    with pytest.raises(ProofFailure, match="hive"):
        _assert_expected_providers(
            _report("sightengine"),
            {"sightengine", "hive"},
        )


def test_forensic_proof_rejects_collapsed_consensus_score():
    report = _report("sightengine", "hive")
    report["signals"]["synthetic_detector_summary"]["consensus_score"] = 0.5
    with pytest.raises(ProofFailure, match="consensus"):
        _assert_expected_providers(report, {"sightengine", "hive"})


def test_evidence_graph_must_contain_each_expected_provider_node():
    graph = {
        "root_node_id": "asset:OV-PROOF",
        "nodes": [
            {
                "evidence_class": "forensic_observation",
                "data": {"provider": "sightengine", "probability": 0.2},
            },
            {
                "evidence_class": "forensic_observation",
                "data": {"provider": "hive", "probability": 0.8},
            },
        ],
    }
    providers = _assert_evidence_graph(
        graph,
        omni_id="OV-PROOF",
        expected_providers={"sightengine", "hive"},
    )
    assert providers == {"sightengine", "hive"}
