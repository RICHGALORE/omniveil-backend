"""Omni Evidence Graph V1.

The graph connects evidence about an asset without collapsing distinct evidence
classes into a single truth claim. Creator declarations, rights claims,
forensic observations, provenance events, certificates, contributor
attributions, and HumanProof process evidence remain separately identifiable.
"""
from __future__ import annotations

import json
from typing import Any

from sqlalchemy.orm import Session

from app.db.models import Asset, AssetMetadata, Certificate, Contributor, ProvenanceEvent


GRAPH_VERSION = "1.0"


def _loads(value: str | None, default):
    if not value:
        return default
    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return default


def _iso(value):
    return value.isoformat() + "Z" if value else None


def _node(node_id: str, node_type: str, evidence_class: str, data: dict[str, Any]) -> dict:
    return {
        "id": node_id,
        "type": node_type,
        "evidence_class": evidence_class,
        "data": data,
    }


def _edge(source: str, target: str, relation: str) -> dict:
    return {"source": source, "target": target, "relation": relation}


def build_evidence_graph(
    db: Session,
    asset: Asset,
    *,
    humanproof: dict | None = None,
) -> dict:
    asset_node_id = f"asset:{asset.omni_id}"
    nodes: list[dict] = []
    edges: list[dict] = []

    nodes.append(
        _node(
            asset_node_id,
            "asset",
            "cryptographic_identity",
            {
                "omni_id": asset.omni_id,
                "asset_id": asset.asset_id,
                "filename": asset.filename,
                "file_type": asset.file_type,
                "asset_type": asset.asset_type,
                "file_size_bytes": asset.file_size_bytes,
                "sha256": asset.sha256,
                "blake3": asset.blake3,
                "phash": asset.phash,
                "created_at": _iso(asset.created_at),
            },
        )
    )

    declaration_id = f"declaration:{asset.omni_id}"
    nodes.append(
        _node(
            declaration_id,
            "creator_declaration",
            "declaration",
            {
                "creator_name": asset.creator_name,
                "ai_disclosure": asset.ai_disclosure,
                "ai_disclosure_complete": asset.ai_disclosure_complete,
                "ai_tools_used": _loads(asset.ai_tools_used_json, []),
                "ai_modification_by_human": asset.ai_modification_by_human,
                "human_authorship_summary": asset.human_authorship_summary,
                "human_contributions": {
                    "creative_direction": asset.human_creative_direction,
                    "editing": asset.human_editing_present,
                    "arrangement": asset.human_arrangement_present,
                    "lyrics": asset.human_lyrics_present,
                    "performance": asset.human_performance_present,
                    "transformation": asset.human_transformation_present,
                },
            },
        )
    )
    edges.append(_edge(declaration_id, asset_node_id, "declares_about"))

    if asset.copyright_owner or asset.license_type:
        rights_id = f"rights:{asset.omni_id}"
        nodes.append(
            _node(
                rights_id,
                "rights_claim",
                "rights_claim",
                {
                    "copyright_owner": asset.copyright_owner,
                    "license_type": asset.license_type,
                    "copyright_readiness_score": asset.copyright_readiness_score,
                    "copyright_readiness_label": asset.copyright_readiness_label,
                },
            )
        )
        edges.append(_edge(rights_id, asset_node_id, "claims_rights_in"))

    contributors = (
        db.query(Contributor)
        .filter(Contributor.omni_id == asset.omni_id)
        .order_by(Contributor.added_at.asc())
        .all()
    )
    for contributor in contributors:
        node_id = f"contributor:{contributor.contributor_id}"
        nodes.append(
            _node(
                node_id,
                "contributor",
                "attribution",
                {
                    "contributor_id": contributor.contributor_id,
                    "name": contributor.contributor_name,
                    "role": contributor.role,
                    "contribution_type": contributor.contribution_type,
                    "creative_contribution_pct": contributor.creative_contribution_pct,
                    "ownership_split_pct": contributor.ownership_split_pct,
                    "ai_assisted_pct": contributor.ai_assisted_pct,
                    "added_at": _iso(contributor.added_at),
                },
            )
        )
        edges.append(_edge(node_id, asset_node_id, "attributed_to"))

    certificates = (
        db.query(Certificate)
        .filter(Certificate.omni_id == asset.omni_id)
        .order_by(Certificate.issued_at.asc())
        .all()
    )
    for certificate in certificates:
        node_id = f"certificate:{certificate.cert_id}"
        cert_body = _loads(certificate.cert_json, {})
        nodes.append(
            _node(
                node_id,
                "certificate",
                "certificate_attestation",
                {
                    "cert_id": certificate.cert_id,
                    "certificate_hash": certificate.certificate_hash,
                    "issued_at": _iso(certificate.issued_at),
                    "issuer": certificate.issuer,
                    "subject_name": certificate.subject_name,
                    "certificate_class": certificate.certificate_class,
                    "signature_algorithm": cert_body.get("signature_algorithm"),
                    "public_key_id": cert_body.get("public_key_id"),
                },
            )
        )
        edges.append(_edge(node_id, asset_node_id, "attests_to"))

    provenance_events = (
        db.query(ProvenanceEvent)
        .filter(ProvenanceEvent.omni_id == asset.omni_id)
        .order_by(ProvenanceEvent.timestamp.asc())
        .all()
    )
    for event in provenance_events:
        node_id = f"provenance:{event.event_id}"
        nodes.append(
            _node(
                node_id,
                "provenance_event",
                "provenance",
                {
                    "event_id": event.event_id,
                    "event_type": event.event_type,
                    "description": event.description,
                    "tool_used": event.tool_used,
                    "human_or_ai": event.human_or_ai,
                    "actor_name": event.actor_name,
                    "timestamp": _iso(event.timestamp),
                    "event_hash": event.event_hash,
                },
            )
        )
        edges.append(_edge(node_id, asset_node_id, "records_event_for"))

    metadata_record = (
        db.query(AssetMetadata)
        .filter(
            AssetMetadata.omni_id == asset.omni_id,
            AssetMetadata.tenant_id == asset.tenant_id,
        )
        .first()
    )
    if metadata_record and metadata_record.anomaly_score is not None:
        node_id = f"forensic:metadata:{asset.omni_id}"
        nodes.append(
            _node(
                node_id,
                "forensic_observation",
                "forensic_observation",
                {
                    "signal": "metadata_anomaly",
                    "score": metadata_record.anomaly_score,
                    "flags": _loads(metadata_record.anomaly_flags_json, []),
                    "engine_version": metadata_record.anomaly_engine_version,
                    "observed_at": _iso(metadata_record.anomaly_scored_at),
                },
            )
        )
        edges.append(_edge(node_id, asset_node_id, "observes"))

    if asset.ai_detection_score is not None:
        node_id = f"forensic:synthetic:{asset.omni_id}"
        nodes.append(
            _node(
                node_id,
                "forensic_observation",
                "forensic_observation",
                {
                    "signal": "synthetic_media_probability",
                    "probability": asset.ai_detection_score,
                    "provider": "sightengine",
                    "model": "genai",
                    "interpretation": "probabilistic_signal_not_determination",
                },
            )
        )
        edges.append(_edge(node_id, asset_node_id, "observes"))

    if humanproof:
        node_id = f"humanproof:{asset.omni_id}"
        nodes.append(
            _node(
                node_id,
                "humanproof_summary",
                "creation_process_evidence",
                humanproof,
            )
        )
        edges.append(_edge(node_id, asset_node_id, "binds_creation_process_to"))

    evidence_counts: dict[str, int] = {}
    for node in nodes:
        evidence_class = str(node["evidence_class"])
        evidence_counts[evidence_class] = evidence_counts.get(evidence_class, 0) + 1

    return {
        "graph_version": GRAPH_VERSION,
        "omni_id": asset.omni_id,
        "root_node_id": asset_node_id,
        "nodes": nodes,
        "edges": edges,
        "evidence_counts": evidence_counts,
        "related_endpoints": {
            "registry": f"/api/v1/registry/assets/{asset.omni_id}",
            "verify": f"/api/v1/verify/{asset.omni_id}",
            "omnispectra": f"/api/v1/spectra/assets/{asset.omni_id}",
            "c2pa": f"/api/v1/c2pa/assets/{asset.omni_id}",
        },
        "principles": {
            "separation_of_evidence": True,
            "no_single_source_of_truth_claim": True,
            "note": (
                "Declarations, forensic observations, rights claims, certificates, "
                "attributions, provenance events, and creation-process evidence remain "
                "separate evidence classes and may corroborate or conflict."
            ),
        },
    }
