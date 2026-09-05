import json
import uuid

from fastapi.testclient import TestClient

import main
from app.api.v1.endpoints import evidence as evidence_endpoint
from app.core.tenant import hash_api_key
from app.db.dpp_models import DigitalProductPassport
from app.db.models import (
    Asset,
    Certificate,
    Client,
    Contributor,
    LiveSplitSession,
    ProvenanceEvent,
)
from app.db.session import SessionLocal


def _ensure_client(raw_key: str, tenant_id: str) -> None:
    main.init_db()
    db = SessionLocal()
    try:
        db.add(
            Client(
                id=str(uuid.uuid4()),
                tenant_id=tenant_id,
                company_name="Evidence Graph Test",
                email=f"evidence-{uuid.uuid4().hex}@example.com",
                status="approved",
                plan="creator",
                api_key_hash=hash_api_key(raw_key),
            )
        )
        db.commit()
    finally:
        db.close()


def _create_asset_bundle(tenant_id: str) -> str:
    token = uuid.uuid4().hex
    omni_id = f"OV-EVIDENCE-{token[:16].upper()}"
    db = SessionLocal()
    try:
        db.add(
            Asset(
                omni_id=omni_id,
                asset_id=f"asset-{token}",
                tenant_id=tenant_id,
                filename="evidence-master.wav",
                file_type="audio/wav",
                original_path=f"/tmp/{token}.wav",
                sha256="a" * 64,
                blake3="b" * 64,
                trust_score=0.81,
                content_label="human",
                creator_name="Evidence Creator",
                copyright_owner="Evidence Rights LLC",
                license_type="all-rights-reserved",
                ai_disclosure="human",
                ai_disclosure_complete=True,
                human_creative_direction=True,
                human_editing_present=True,
                copyright_readiness_score=0.9,
                copyright_readiness_label="strong",
            )
        )
        db.add(
            Contributor(
                contributor_id=f"contrib-{token}",
                omni_id=omni_id,
                contributor_name="Evidence Creator",
                role="producer",
                contribution_type="human",
                creative_contribution_pct=100.0,
                ownership_split_pct=100.0,
                ai_assisted_pct=0.0,
            )
        )
        split_contributors = [
            {
                "name": "Evidence Creator",
                "role": "producer",
                "contribution_type": "human",
                "creative_contribution_pct": 100.0,
                "ownership_split_pct": 100.0,
                "ai_assisted_pct": 0.0,
                "wallet_address": "private-wallet-not-for-graph",
            }
        ]
        db.add(
            LiveSplitSession(
                session_id=f"split-{token}",
                omni_id=omni_id,
                tenant_id=tenant_id,
                session_name="Evidence Master Split",
                status="locked",
                contributors_json=json.dumps(split_contributors),
                session_hash="e" * 64,
            )
        )
        db.add(
            DigitalProductPassport(
                passport_id=f"dpp-{token}",
                omni_id=omni_id,
                tenant_id=tenant_id,
                passport_level="item",
                product_name="Evidence Luxury Item",
                brand_name="Evidence Brand",
                gtin14="09506000151519",
                serial_number="EVIDENCE-1",
                data_carrier_type="qr",
                canonical_gs1_uri="https://id.gs1.org/01/09506000151519/21/EVIDENCE-1",
                resolver_uri="https://id.evidence.example/01/09506000151519/21/EVIDENCE-1",
                gs1_uri_syntax_version="1.7.0",
                gs1_resolver_standard_version="1.2.1",
                regulatory_framework="Regulation (EU) 2024/1781",
                regulatory_status="readiness_only",
            )
        )
        db.add(
            Certificate(
                cert_id=f"cert-{token}",
                omni_id=omni_id,
                certificate_hash="c" * 64,
                issuer="Omni Veil Trust OS",
                subject_name="Evidence Creator",
                certificate_class="standard",
                cert_json=json.dumps(
                    {
                        "signature_algorithm": "Ed25519",
                        "public_key_id": "OV-ROOT-TEST-001",
                        "signature": "private-signature-material-not-for-graph",
                    }
                ),
                signature="private-signature-material-not-for-graph",
            )
        )
        db.add(
            ProvenanceEvent(
                event_id=f"event-{token}",
                omni_id=omni_id,
                event_type="upload",
                description="Original registered",
                tool_used="Omni Veil Ingest API",
                human_or_ai="system",
                actor_name="Evidence Creator",
                event_hash="d" * 64,
            )
        )
        db.commit()
        return omni_id
    finally:
        db.close()


def test_evidence_graph_keeps_evidence_classes_separate_and_is_tenant_scoped(monkeypatch):
    owner_key = f"ov_live_graph_owner_{uuid.uuid4().hex}"
    other_key = f"ov_live_graph_other_{uuid.uuid4().hex}"
    owner_tenant = f"graph-owner-{uuid.uuid4().hex}"
    other_tenant = f"graph-other-{uuid.uuid4().hex}"
    _ensure_client(owner_key, owner_tenant)
    _ensure_client(other_key, other_tenant)
    omni_id = _create_asset_bundle(owner_tenant)

    monkeypatch.setattr(
        evidence_endpoint,
        "get_public_humanproof_summary",
        lambda db, requested_omni_id: {
            "status": "complete",
            "event_count": 5,
            "chain_integrity": {"valid": True, "event_count": 5},
            "ai_disclosure": {"used": False, "tools": [], "role": None},
            "location": {"level": "coarse", "public_summary": "Las Vegas, NV"},
            "asset_bound": requested_omni_id == omni_id,
        },
    )

    with TestClient(main.app, raise_server_exceptions=False) as client:
        response = client.get(
            f"/api/v1/evidence/assets/{omni_id}",
            headers={"X-API-Key": owner_key},
        )
        assert response.status_code == 200, response.text
        graph = response.json()

        assert graph["graph_version"] == "1.3"
        assert graph["root_node_id"] == f"asset:{omni_id}"
        assert graph["principles"]["separation_of_evidence"] is True
        assert graph["principles"]["no_single_source_of_truth_claim"] is True

        classes = {node["evidence_class"] for node in graph["nodes"]}
        assert {
            "cryptographic_identity",
            "declaration",
            "rights_claim",
            "rights_record",
            "product_passport_record",
            "attribution",
            "certificate_attestation",
            "provenance",
            "creation_process_evidence",
        }.issubset(classes)

        declaration = next(node for node in graph["nodes"] if node["type"] == "creator_declaration")
        rights = next(node for node in graph["nodes"] if node["type"] == "rights_claim")
        rights_record = next(node for node in graph["nodes"] if node["type"] == "live_split_record")
        dpp_record = next(node for node in graph["nodes"] if node["type"] == "digital_product_passport")
        contributor = next(node for node in graph["nodes"] if node["type"] == "contributor")

        assert declaration["id"] != rights["id"]
        assert rights["id"] != rights_record["id"]
        assert declaration["data"]["ai_disclosure"] == "human"
        assert rights["data"]["copyright_owner"] == "Evidence Rights LLC"
        assert rights_record["data"]["status"] == "locked"
        assert rights_record["data"]["ownership_total_pct"] == 100.0
        assert rights_record["data"]["integrity"]["locked_or_finalized"] is True
        assert rights_record["data"]["integrity"]["session_hash_present"] is True
        assert rights_record["data"]["contributors"][0]["name"] == "Evidence Creator"

        assert dpp_record["evidence_class"] == "product_passport_record"
        assert dpp_record["data"]["regulatory_status"] == "readiness_only"
        assert dpp_record["data"]["readiness"]["checks"]["physical_data_carrier_presence_verified"] is False
        assert "does not certify" in dpp_record["data"]["readiness"]["statement"]
        assert {
            "source": dpp_record["id"],
            "target": f"asset:{omni_id}",
            "relation": "documents_product_identity_for",
        } in graph["edges"]

        assert {
            "source": contributor["id"],
            "target": rights_record["id"],
            "relation": "included_in_rights_record",
        } in graph["edges"]
        assert {
            "source": rights_record["id"],
            "target": rights["id"],
            "relation": "documents_declared_rights",
        } in graph["edges"]

        certificate = next(node for node in graph["nodes"] if node["type"] == "certificate")
        assert certificate["data"]["signature_algorithm"] == "Ed25519"
        assert certificate["data"]["public_key_id"] == "OV-ROOT-TEST-001"
        assert "signature" not in certificate["data"]

        serialized = json.dumps(graph)
        assert "tenant_id" not in serialized
        assert "private-signature-material-not-for-graph" not in serialized
        assert "private-wallet-not-for-graph" not in serialized

        denied = client.get(
            f"/api/v1/evidence/assets/{omni_id}",
            headers={"X-API-Key": other_key},
        )
        assert denied.status_code == 404
