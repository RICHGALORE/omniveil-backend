#!/usr/bin/env python3
"""Run a live Omni Veil Trust OS production proof.

This script intentionally creates a new, non-commercial smoke-test asset. It proves:
- liveness and strict production readiness
- authenticated ingest + fresh registration
- HumanProof chain creation, asset binding, closure, and verification
- public Verify + Registry visibility
- Ed25519 certificate validity and production key identity
- Evidence Graph availability
- cross-layer Fact Integrity consistency

It never prints or stores the API key.

Examples:
  OV_API_KEY=... python scripts/production_proof.py
  OV_API_KEY=... OV_EXPECTED_SIGNING_KEY_ID=OV-ROOT-PROD-001 \
      python scripts/production_proof.py --report production-proof.json

After a deploy/restart, recheck persistence:
  OV_API_KEY=... python scripts/production_proof.py \
      --recheck-omni-id OV-... --expected-cert-id <cert-id>
"""

from __future__ import annotations

import argparse
import io
import json
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
from PIL import Image
from PIL.PngImagePlugin import PngInfo


DEFAULT_BASE_URL = "https://omniveil-backend.onrender.com"
DEV_KEY_IDS = {"OV-ROOT-DEV-001"}


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


def _make_png(run_id: str) -> bytes:
    # Unique bytes on every run guarantee a fresh Omni ID without pretending this
    # operational test artifact is commercial creative work.
    seed = uuid.UUID(run_id).bytes
    image = Image.new("RGB", (48, 48), (seed[0], seed[1], seed[2]))
    metadata = PngInfo()
    metadata.add_text("OmniVeilProductionProofRun", run_id)
    metadata.add_text("Purpose", "Infrastructure smoke test; not a creative-authorship claim.")
    output = io.BytesIO()
    image.save(output, format="PNG", pnginfo=metadata)
    return output.getvalue()


def _public_assertions(
    payload: dict[str, Any],
    *,
    label: str,
    omni_id: str,
    expect_humanproof: bool,
) -> None:
    observed_id = payload.get("omni_id")
    if observed_id is not None:
        _require(observed_id == omni_id, f"{label} returned the wrong Omni ID")

    if expect_humanproof:
        hp = payload.get("humanproof")
        _require(isinstance(hp, dict), f"{label} did not expose the HumanProof summary")
        _require(hp.get("status") == "complete", f"{label} HumanProof is not complete")
        _require(hp.get("asset_bound") is True, f"{label} HumanProof is not asset-bound")
        chain = hp.get("chain_integrity")
        _require(
            isinstance(chain, dict) and chain.get("valid") is True,
            f"{label} HumanProof chain is not valid",
        )


def _check_certificate(
    client: httpx.Client,
    *,
    omni_id: str,
    expected_key_id: str | None,
    expected_cert_id: str | None,
) -> dict[str, Any]:
    cert = _json(
        client.get(f"/api/v1/certificates/{omni_id}/verify"),
        "certificate verification",
    )
    _require(cert.get("valid") is True, "certificate signature is not valid")
    _require(cert.get("signature_valid") is True, "Ed25519 signature check failed")
    _require(
        cert.get("signature_algorithm") == "Ed25519",
        "certificate is not using Ed25519",
    )

    key_id = cert.get("public_key_id")
    _require(isinstance(key_id, str) and key_id, "certificate public_key_id is missing")
    _require(key_id not in DEV_KEY_IDS, f"production certificate used development key {key_id}")
    if expected_key_id:
        _require(
            key_id == expected_key_id,
            f"certificate key mismatch: expected {expected_key_id}, observed {key_id}",
        )
    if expected_cert_id:
        _require(
            cert.get("cert_id") == expected_cert_id,
            "certificate ID changed or a different certificate was returned",
        )
    return cert


def _check_ready(client: httpx.Client) -> tuple[dict[str, Any], dict[str, Any]]:
    health = _json(client.get("/health"), "health")
    ready = _json(client.get("/ready"), "readiness")
    _require(ready.get("ready") is True, "service is not production-ready")
    checks = ready.get("checks")
    _require(isinstance(checks, dict), "readiness checks are missing")
    for required in ("database", "storage", "trust_signing"):
        _require(checks.get(required) is True, f"readiness check failed: {required}")

    environment = ready.get("environment") or health.get("env")
    _require(environment == "production", f"expected production environment, observed {environment!r}")
    return health, ready


def _recheck_existing(
    client: httpx.Client,
    *,
    api_key: str,
    omni_id: str,
    expected_key_id: str | None,
    expected_cert_id: str | None,
) -> dict[str, Any]:
    health, ready = _check_ready(client)

    verify = _json(client.get(f"/api/v1/verify/{omni_id}"), "public Verify")
    _public_assertions(
        verify,
        label="public Verify",
        omni_id=omni_id,
        expect_humanproof=True,
    )

    registry = _json(
        client.get(f"/api/v1/registry/assets/{omni_id}"),
        "public Registry",
    )
    _public_assertions(
        registry,
        label="public Registry",
        omni_id=omni_id,
        expect_humanproof=True,
    )

    cert = _check_certificate(
        client,
        omni_id=omni_id,
        expected_key_id=expected_key_id,
        expected_cert_id=expected_cert_id,
    )

    integrity = _json(
        client.get(
            f"/api/v1/assets/{omni_id}/integrity",
            headers=_headers(api_key),
        ),
        "Fact Integrity",
    )
    _require(
        integrity.get("status") == "consistent",
        f"Fact Integrity is {integrity.get('status')!r}, expected 'consistent'",
    )
    _require(integrity.get("mismatch_count") == 0, "Fact Integrity found mismatches")

    evidence = _json(
        client.get(
            f"/api/v1/evidence/assets/{omni_id}",
            headers=_headers(api_key),
        ),
        "Evidence Graph",
    )
    _require(evidence.get("root_node_id") == f"asset:{omni_id}", "Evidence Graph root mismatch")
    nodes = evidence.get("nodes")
    _require(isinstance(nodes, list) and nodes, "Evidence Graph contains no evidence nodes")
    classes = {
        node.get("evidence_class")
        for node in nodes
        if isinstance(node, dict)
    }
    _require("certificate_attestation" in classes, "Evidence Graph lacks certificate evidence")
    _require("creation_process_evidence" in classes, "Evidence Graph lacks HumanProof evidence")

    return {
        "mode": "recheck",
        "checked_at": _now_iso(),
        "omni_id": omni_id,
        "cert_id": cert.get("cert_id"),
        "public_key_id": cert.get("public_key_id"),
        "health": health,
        "ready": ready,
        "fact_integrity_status": integrity.get("status"),
        "evidence_graph_version": evidence.get("graph_version"),
        "persistence_recheck": "passed",
    }


def _create_proof(
    client: httpx.Client,
    *,
    api_key: str,
    expected_key_id: str | None,
) -> dict[str, Any]:
    health, ready = _check_ready(client)
    headers = _headers(api_key)
    run_id = str(uuid.uuid4())

    started = _json(
        client.post(
            "/api/v1/humanproof/sessions",
            headers=headers,
            json={
                "creator_id": "production-proof-runner",
                "source_type": "system",
                "source_name": "scripts/production_proof.py",
                "location": {"level": "none"},
                "payload": {
                    "run_id": run_id,
                    "purpose": "production_infrastructure_proof",
                },
            },
        ),
        "HumanProof session start",
        expected=201,
    )
    session_id = started.get("session_id")
    _require(isinstance(session_id, str) and session_id, "HumanProof session_id is missing")

    artifact = _make_png(run_id)

    _json(
        client.post(
            f"/api/v1/humanproof/sessions/{session_id}/events",
            headers=headers,
            json={
                "event_type": "work_exported",
                "source_type": "system",
                "source_name": "scripts/production_proof.py",
                "creator_id": "production-proof-runner",
                "payload": {
                    "run_id": run_id,
                    "artifact_kind": "unique PNG infrastructure smoke asset",
                },
            },
        ),
        "HumanProof work_exported event",
        expected=201,
    )

    _json(
        client.post(
            f"/api/v1/humanproof/sessions/{session_id}/events",
            headers=headers,
            json={
                "event_type": "ai_tool_disclosed",
                "source_type": "system",
                "source_name": "scripts/production_proof.py",
                "creator_id": "production-proof-runner",
                "ai_disclosure": {
                    "used": False,
                    "tools": [],
                    "role": None,
                },
                "payload": {
                    "scope": "smoke-test artifact generation",
                    "statement": "No generative-AI system created the smoke-test image bytes.",
                },
            },
        ),
        "HumanProof AI disclosure event",
        expected=201,
    )

    upload = _json(
        client.post(
            "/api/v1/upload",
            headers=headers,
            files={"file": ("omniveil-production-proof.png", artifact, "image/png")},
            data={
                "provenance_json": json.dumps(
                    {
                        "creator_name": "Omni Veil Production Proof Runner",
                        "ai_disclosure": "human",
                        "ai_disclosure_complete": True,
                        "human_authorship_summary": (
                            "Operational smoke-test artifact created deterministically by "
                            "the production proof runner; not a commercial authorship claim."
                        ),
                    }
                ),
                "options_json": json.dumps(
                    {
                        "visible_watermark": True,
                        "invisible_watermark": True,
                    }
                ),
            },
        ),
        "authenticated ingest",
    )
    _require(upload.get("registration_reused") is False, "smoke upload unexpectedly reused an asset")
    omni_id = upload.get("omni_id")
    cert_id = upload.get("cert_id")
    _require(isinstance(omni_id, str) and omni_id, "ingest did not return an Omni ID")
    _require(isinstance(cert_id, str) and cert_id, "ingest did not return a certificate ID")
    _require(upload.get("watermark_applied") is True, "watermark write path was not exercised")

    _json(
        client.post(
            f"/api/v1/humanproof/sessions/{session_id}/events",
            headers=headers,
            json={
                "event_type": "asset_registered",
                "source_type": "registry",
                "source_name": "Omni Veil production API",
                "creator_id": "production-proof-runner",
                "omni_id": omni_id,
                "payload": {"omni_id": omni_id, "cert_id": cert_id, "run_id": run_id},
            },
        ),
        "HumanProof asset binding event",
        expected=201,
    )

    closed = _json(
        client.post(
            f"/api/v1/humanproof/sessions/{session_id}/close",
            headers=headers,
            json={
                "source_type": "system",
                "source_name": "scripts/production_proof.py",
                "creator_id": "production-proof-runner",
            },
        ),
        "HumanProof session close",
    )
    _require(closed.get("status") == "complete", "HumanProof session did not close complete")

    hp_verify = _json(
        client.get(
            f"/api/v1/humanproof/sessions/{session_id}/verify",
            headers=headers,
        ),
        "HumanProof chain verification",
    )
    chain = hp_verify.get("chain_integrity")
    _require(
        isinstance(chain, dict) and chain.get("valid") is True,
        "HumanProof event chain failed verification",
    )

    cert = _check_certificate(
        client,
        omni_id=omni_id,
        expected_key_id=expected_key_id,
        expected_cert_id=cert_id,
    )

    verify = _json(client.get(f"/api/v1/verify/{omni_id}"), "public Verify")
    _public_assertions(
        verify,
        label="public Verify",
        omni_id=omni_id,
        expect_humanproof=True,
    )

    registry = _json(
        client.get(f"/api/v1/registry/assets/{omni_id}"),
        "public Registry",
    )
    _public_assertions(
        registry,
        label="public Registry",
        omni_id=omni_id,
        expect_humanproof=True,
    )

    integrity = _json(
        client.get(
            f"/api/v1/assets/{omni_id}/integrity",
            headers=headers,
        ),
        "Fact Integrity",
    )
    _require(
        integrity.get("status") == "consistent",
        f"Fact Integrity is {integrity.get('status')!r}, expected 'consistent'",
    )
    _require(integrity.get("mismatch_count") == 0, "Fact Integrity found mismatches")

    evidence = _json(
        client.get(
            f"/api/v1/evidence/assets/{omni_id}",
            headers=headers,
        ),
        "Evidence Graph",
    )
    _require(evidence.get("root_node_id") == f"asset:{omni_id}", "Evidence Graph root mismatch")
    nodes = evidence.get("nodes")
    _require(isinstance(nodes, list) and nodes, "Evidence Graph contains no evidence nodes")
    classes = {
        node.get("evidence_class")
        for node in nodes
        if isinstance(node, dict)
    }
    _require("certificate_attestation" in classes, "Evidence Graph lacks certificate evidence")
    _require("creation_process_evidence" in classes, "Evidence Graph lacks HumanProof evidence")

    return {
        "mode": "create",
        "checked_at": _now_iso(),
        "run_id": run_id,
        "omni_id": omni_id,
        "asset_id": upload.get("asset_id"),
        "cert_id": cert_id,
        "humanproof_session_id": session_id,
        "public_key_id": cert.get("public_key_id"),
        "health": health,
        "ready": ready,
        "watermark_applied": upload.get("watermark_applied"),
        "fact_integrity_status": integrity.get("status"),
        "evidence_graph_version": evidence.get("graph_version"),
        "next_step": (
            "After a Render restart/deploy, run --recheck-omni-id with this Omni ID "
            "and --expected-cert-id with this certificate ID to prove persistence."
        ),
    }


def _write_report(path: str | None, report: dict[str, Any]) -> None:
    if not path:
        return
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Prove the live Omni Veil production Trust OS path.")
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
    parser.add_argument(
        "--expected-key-id",
        default=os.getenv("OV_EXPECTED_SIGNING_KEY_ID"),
        help="Expected production Ed25519 public key ID",
    )
    parser.add_argument(
        "--report",
        default="production-proof.json",
        help="Write a secret-free JSON proof report to this path; use '' to disable",
    )
    parser.add_argument(
        "--recheck-omni-id",
        help="Recheck an existing proof asset after a restart/deploy instead of creating a new one",
    )
    parser.add_argument(
        "--expected-cert-id",
        help="Certificate ID expected during persistence recheck",
    )
    parser.add_argument("--timeout", type=float, default=60.0)
    return parser


def main() -> int:
    args = _build_parser().parse_args()
    if not args.api_key:
        print("ERROR: OV_API_KEY or --api-key is required", file=sys.stderr)
        return 2

    base_url = args.base_url.rstrip("/")
    try:
        with httpx.Client(
            base_url=base_url,
            timeout=args.timeout,
            follow_redirects=True,
            headers={"User-Agent": "OmniVeilProductionProof/1.0"},
        ) as client:
            if args.recheck_omni_id:
                report = _recheck_existing(
                    client,
                    api_key=args.api_key,
                    omni_id=args.recheck_omni_id,
                    expected_key_id=args.expected_key_id,
                    expected_cert_id=args.expected_cert_id,
                )
            else:
                report = _create_proof(
                    client,
                    api_key=args.api_key,
                    expected_key_id=args.expected_key_id,
                )
    except (httpx.HTTPError, ProofFailure) as exc:
        print(f"PRODUCTION PROOF FAILED: {exc}", file=sys.stderr)
        return 1

    report["base_url"] = base_url
    _write_report(args.report or None, report)

    print("OMNI VEIL PRODUCTION PROOF PASSED")
    print(f"mode: {report['mode']}")
    print(f"omni_id: {report['omni_id']}")
    print(f"cert_id: {report.get('cert_id')}")
    print(f"public_key_id: {report.get('public_key_id')}")
    print(f"fact_integrity: {report.get('fact_integrity_status')}")
    print(f"evidence_graph: {report.get('evidence_graph_version')}")
    if args.report:
        print(f"report: {args.report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
