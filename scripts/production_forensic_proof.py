#!/usr/bin/env python3
"""Prove live multi-provider OmniSpectra evidence for a registered asset.

This runner is intentionally separate from the core production infrastructure
proof. Use `scripts/production_proof.py` first to prove database, durable
storage, signing, HumanProof, Registry, Verify, Fact Integrity, and Evidence
Graph. Then run this script against that Omni ID (or a real flagship asset) to
prove configured external forensic providers are live and their observations
persist independently.

Examples:
  OV_API_KEY=... python scripts/production_forensic_proof.py --omni-id OV-...

  OV_API_KEY=... OV_EXPECTED_DETECTOR_PROVIDERS=sightengine,hive \
      python scripts/production_forensic_proof.py --omni-id OV-... \
      --report production-forensic-proof.json

Use --no-refresh after a restart/deploy to prove the previously persisted
provider observations still exist without calling the external vendors again.

The report never prints or stores the tenant API key and never converts model
probabilities into an authenticity/authorship determination.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx


DEFAULT_BASE_URL = "https://omniveil-backend.onrender.com"
DEFAULT_EXPECTED_PROVIDERS = "sightengine,hive"


class ProofFailure(RuntimeError):
    pass


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ProofFailure(message)


def _json(response: httpx.Response, label: str, expected: int = 200) -> dict[str, Any]:
    if response.status_code != expected:
        snippet = response.text[:500].replace("\n", " ")
        raise ProofFailure(
            f"{label} returned HTTP {response.status_code}, expected {expected}: {snippet}"
        )
    try:
        payload = response.json()
    except ValueError as exc:
        raise ProofFailure(f"{label} did not return JSON") from exc
    if not isinstance(payload, dict):
        raise ProofFailure(f"{label} returned non-object JSON")
    return payload


def _headers(api_key: str) -> dict[str, str]:
    return {"X-API-Key": api_key}


def _providers(value: str) -> set[str]:
    return {
        item.strip().lower()
        for item in value.split(",")
        if item.strip()
    }


def _detector_state(report: dict[str, Any]) -> tuple[set[str], list[dict[str, Any]]]:
    signals = report.get("signals")
    _require(isinstance(signals, dict), "OmniSpectra signals are missing")

    summary = signals.get("synthetic_detector_summary")
    _require(isinstance(summary, dict), "synthetic detector summary is missing")
    _require(
        summary.get("consensus_score") is None,
        "OmniSpectra unexpectedly collapsed provider scores into a consensus score",
    )

    providers = {
        str(provider).strip().lower()
        for provider in (summary.get("providers") or [])
        if str(provider).strip()
    }

    observations = signals.get("synthetic_detectors")
    _require(isinstance(observations, list), "synthetic detector observations are missing")
    normalized = [item for item in observations if isinstance(item, dict)]
    return providers, normalized


def _assert_expected_providers(
    report: dict[str, Any],
    expected_providers: set[str],
) -> tuple[set[str], list[dict[str, Any]]]:
    providers, observations = _detector_state(report)
    missing = sorted(expected_providers - providers)
    _require(
        not missing,
        f"expected forensic provider(s) missing from OmniSpectra: {', '.join(missing)}",
    )

    for provider in expected_providers:
        provider_rows = [
            item
            for item in observations
            if str(item.get("provider") or "").strip().lower() == provider
        ]
        _require(provider_rows, f"no persisted observation row found for provider {provider}")
        for row in provider_rows:
            probability = row.get("probability")
            _require(
                isinstance(probability, (int, float)) and 0.0 <= float(probability) <= 1.0,
                f"provider {provider} returned an invalid probability",
            )
            _require(
                row.get("status") == "available",
                f"provider {provider} observation is not marked available",
            )

    return providers, observations


def _assert_evidence_graph(
    graph: dict[str, Any],
    *,
    omni_id: str,
    expected_providers: set[str],
) -> set[str]:
    _require(
        graph.get("root_node_id") == f"asset:{omni_id}",
        "Evidence Graph root does not match the requested asset",
    )
    nodes = graph.get("nodes")
    _require(isinstance(nodes, list), "Evidence Graph nodes are missing")

    forensic_providers = {
        str((node.get("data") or {}).get("provider") or "").strip().lower()
        for node in nodes
        if isinstance(node, dict)
        and node.get("evidence_class") == "forensic_observation"
        and isinstance(node.get("data"), dict)
        and (node.get("data") or {}).get("provider")
    }
    missing = sorted(expected_providers - forensic_providers)
    _require(
        not missing,
        f"Evidence Graph is missing persisted provider node(s): {', '.join(missing)}",
    )
    return forensic_providers


def run_proof(
    client: httpx.Client,
    *,
    api_key: str,
    omni_id: str,
    expected_providers: set[str],
    refresh: bool,
) -> dict[str, Any]:
    headers = _headers(api_key)

    if refresh:
        report = _json(
            client.post(
                f"/api/v1/spectra/assets/{omni_id}/detectors",
                headers=headers,
            ),
            "registered detector refresh",
        )
        refresh_meta = report.get("detector_refresh")
        _require(isinstance(refresh_meta, dict), "detector refresh metadata is missing")
        _require(
            refresh_meta.get("registration_rewritten") is False,
            "detector refresh rewrote registration facts",
        )
        _require(
            refresh_meta.get("trust_score_rewritten") is False,
            "detector refresh rewrote the historical Trust Score",
        )
        persisted_count = refresh_meta.get("persisted_observation_count")
        _require(
            isinstance(persisted_count, int) and persisted_count > 0,
            "detector refresh persisted no observations",
        )
    else:
        report = _json(
            client.get(
                f"/api/v1/spectra/assets/{omni_id}",
                headers=headers,
            ),
            "registered OmniSpectra report",
        )

    providers, observations = _assert_expected_providers(report, expected_providers)

    graph = _json(
        client.get(
            f"/api/v1/evidence/assets/{omni_id}",
            headers=headers,
        ),
        "Evidence Graph",
    )
    graph_providers = _assert_evidence_graph(
        graph,
        omni_id=omni_id,
        expected_providers=expected_providers,
    )

    observation_summary = [
        {
            "provider": item.get("provider"),
            "model": item.get("model"),
            "signal": item.get("signal"),
            "probability": item.get("probability"),
            "observed_at": item.get("observed_at"),
        }
        for item in observations
        if str(item.get("provider") or "").strip().lower() in expected_providers
    ]

    return {
        "mode": "refresh" if refresh else "persistence_recheck",
        "checked_at": _now_iso(),
        "omni_id": omni_id,
        "expected_providers": sorted(expected_providers),
        "observed_providers": sorted(providers),
        "evidence_graph_providers": sorted(graph_providers),
        "evidence_graph_version": graph.get("graph_version"),
        "consensus_score": None,
        "observations": observation_summary,
        "registration_rewritten": False,
        "trust_score_rewritten": False,
        "interpretation": (
            "Provider-specific probabilistic forensic observations were preserved "
            "independently. This proof is not an authenticity, authorship, copyright, "
            "or fraud determination."
        ),
    }


def _write_report(path: str | None, report: dict[str, Any]) -> None:
    if not path:
        return
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Prove live independent synthetic-media providers in OmniSpectra."
    )
    parser.add_argument(
        "--base-url",
        default=os.getenv("OV_BASE_URL", DEFAULT_BASE_URL),
        help="Omni Veil backend base URL",
    )
    parser.add_argument(
        "--api-key",
        default=os.getenv("OV_API_KEY"),
        help="Tenant API key (prefer OV_API_KEY environment variable)",
    )
    parser.add_argument("--omni-id", required=True, help="Registered asset Omni ID")
    parser.add_argument(
        "--expected-providers",
        default=os.getenv("OV_EXPECTED_DETECTOR_PROVIDERS", DEFAULT_EXPECTED_PROVIDERS),
        help="Comma-separated provider names expected in OmniSpectra",
    )
    parser.add_argument(
        "--no-refresh",
        action="store_true",
        help="Read persisted observations without making new external detector calls",
    )
    parser.add_argument(
        "--report",
        default="production-forensic-proof.json",
        help="Write a secret-free JSON proof report to this path; use '' to disable",
    )
    parser.add_argument("--timeout", type=float, default=90.0)
    return parser


def main() -> int:
    args = _build_parser().parse_args()
    if not args.api_key:
        print("ERROR: OV_API_KEY or --api-key is required", file=sys.stderr)
        return 2

    expected = _providers(args.expected_providers)
    if not expected:
        print("ERROR: at least one expected detector provider is required", file=sys.stderr)
        return 2

    base_url = args.base_url.rstrip("/")
    try:
        with httpx.Client(
            base_url=base_url,
            timeout=args.timeout,
            follow_redirects=True,
            headers={"User-Agent": "OmniVeilProductionForensicProof/1.0"},
        ) as client:
            report = run_proof(
                client,
                api_key=args.api_key,
                omni_id=args.omni_id,
                expected_providers=expected,
                refresh=not args.no_refresh,
            )
    except (httpx.HTTPError, ProofFailure) as exc:
        print(f"PRODUCTION FORENSIC PROOF FAILED: {exc}", file=sys.stderr)
        return 1

    report["base_url"] = base_url
    _write_report(args.report or None, report)

    print("OMNI VEIL PRODUCTION FORENSIC PROOF PASSED")
    print(f"mode: {report['mode']}")
    print(f"omni_id: {report['omni_id']}")
    print(f"providers: {', '.join(report['observed_providers'])}")
    print(f"evidence_graph: {report.get('evidence_graph_version')}")
    if args.report:
        print(f"report: {args.report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
