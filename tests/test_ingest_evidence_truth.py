import io
import json
import uuid
import zipfile

from fastapi.testclient import TestClient
from PIL import Image

import main
from app.core.tenant import hash_api_key
from app.db.models import Client
from app.db.session import SessionLocal


RAW_KEY = "ov_ingest_evidence_truth_test_key"
TENANT_ID = "ingest-evidence-truth-tenant"
OTHER_KEY = "ov_ingest_evidence_truth_other_key"
OTHER_TENANT_ID = "ingest-evidence-truth-other-tenant"


def _ensure_client(
    raw_key: str = RAW_KEY,
    tenant_id: str = TENANT_ID,
    email: str = "ingest-evidence-truth@example.com",
) -> None:
    db = SessionLocal()
    try:
        key_hash = hash_api_key(raw_key)
        if not db.query(Client).filter(Client.api_key_hash == key_hash).first():
            db.add(Client(
                id=str(uuid.uuid4()),
                tenant_id=tenant_id,
                company_name=f"{tenant_id} Test",
                email=email,
                status="approved",
                plan="creator",
                api_key_hash=key_hash,
            ))
            db.commit()
    finally:
        db.close()


def _png_bytes() -> bytes:
    image = Image.new("RGB", (24, 24), tuple(uuid.uuid4().bytes[:3]))
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    return buffer.getvalue()


def _upload_bytes(
    client: TestClient,
    raw_key: str,
    provenance: dict,
    data: bytes,
) -> dict:
    response = client.post(
        "/api/v1/upload",
        headers={"X-API-Key": raw_key},
        files={"file": (f"truth-{uuid.uuid4()}.png", data, "image/png")},
        data={
            "provenance_json": json.dumps(provenance),
            "options_json": json.dumps({
                "visible_watermark": False,
                "invisible_watermark": False,
            }),
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


def _upload(client: TestClient, provenance: dict) -> dict:
    return _upload_bytes(client, RAW_KEY, provenance, _png_bytes())


def test_creator_attribution_does_not_become_ownership_or_human_evidence():
    with TestClient(main.app, raise_server_exceptions=False) as client:
        _ensure_client()
        uploaded = _upload(client, {
            "creator_name": "Evidence Tester",
            "ai_disclosure": "human",
            "ai_disclosure_complete": True,
        })

        assert uploaded["creator_name"] == "Evidence Tester"
        assert uploaded["copyright_owner"] is None
        assert uploaded["license_type"] is None
        assert uploaded["section_a_human_contributions"]["contributions"] == []
        assert uploaded["section_a_human_contributions"]["contributors"] == []
        assert uploaded["section_c_ownership_splits"]["copyright_owner"] == ""
        assert uploaded["section_c_ownership_splits"]["splits"] == []

        detail = client.get(
            f"/api/v1/certificates/{uploaded['cert_id']}",
            headers={"X-API-Key": RAW_KEY},
        )
        assert detail.status_code == 200, detail.text
        certificate = detail.json()["certificate"]
        assert certificate["copyright_owner"] == ""
        assert certificate["section_c_ownership_splits"]["splits"] == []
        assert certificate["public_key_id"] == "OV-ROOT-DEV-001"

        copyright_report = client.get(
            f"/api/v1/assets/{uploaded['omni_id']}/copyright-report",
            headers={"X-API-Key": RAW_KEY},
        )
        assert copyright_report.status_code == 200, copyright_report.text
        report = copyright_report.json()
        assert report["human_contributors"] == []
        assert report["contributor_declarations"] == []
        assert report["ownership_declarations"]["copyright_owner"] is None
        assert report["ownership_declarations"]["ownership_splits"] == []
        assert report["ownership_declarations"]["ownership_declared"] is False


def test_ai_assisted_disclosure_is_not_rewritten_as_ai_generated():
    with TestClient(main.app, raise_server_exceptions=False) as client:
        _ensure_client()
        uploaded = _upload(client, {
            "creator_name": "Evidence Tester",
            "ai_disclosure": "ai_assisted",
            "ai_disclosure_complete": True,
            "ai_tools_used": ["Suno"],
            "human_creative_direction": True,
            "ai_modification_by_human": True,
        })

        assert uploaded["ai_disclosure"] == "ai_assisted"
        assert uploaded["content_label"] == "ai_assisted"
        assert uploaded["certificate_class"] == "ai_assisted"
        assert uploaded["section_b_ai_contributions"]["ai_tools_used"] == ["Suno"]
        assert uploaded["copyright_owner"] is None


def test_legacy_false_generated_flag_with_ai_tools_normalizes_to_ai_assisted():
    with TestClient(main.app, raise_server_exceptions=False) as client:
        _ensure_client()
        uploaded = _upload(client, {
            "creator_name": "Evidence Tester",
            "is_ai_generated": False,
            "ai_disclosure_complete": True,
            "ai_tools_used": ["Assistive Tool"],
            "human_creative_direction": True,
        })

        assert uploaded["ai_disclosure"] == "ai_assisted"
        assert uploaded["content_label"] == "ai_assisted"


def test_human_disclosure_rejects_specific_ai_tools_as_contradictory():
    with TestClient(main.app, raise_server_exceptions=False) as client:
        _ensure_client()
        response = client.post(
            "/api/v1/upload",
            headers={"X-API-Key": RAW_KEY},
            files={"file": ("contradiction.png", _png_bytes(), "image/png")},
            data={
                "provenance_json": json.dumps({
                    "creator_name": "Evidence Tester",
                    "ai_disclosure": "human",
                    "ai_tools_used": ["Suno"],
                }),
                "options_json": "{}",
            },
        )

        assert response.status_code == 400
        assert "cannot be human" in response.json()["detail"]


def test_stored_names_percentages_and_counts_report_without_drift():
    with TestClient(main.app, raise_server_exceptions=False) as client:
        _ensure_client()
        uploaded = _upload(client, {
            "creator_name": "Exact Creator",
            "copyright_owner": "Exact Rights LLC",
            "license_type": "Exact Custom License",
            "ai_disclosure": "ai_assisted",
            "ai_disclosure_complete": True,
            "ai_tools_used": ["Exact Tool"],
            "human_editing_present": True,
            "contributors": [
                {
                    "name": "Exact Contributor",
                    "role": "Producer",
                    "creative_contribution_pct": 0,
                    "ownership_split_pct": 100,
                    "ai_assisted_pct": 0,
                }
            ],
        })
        headers = {"X-API-Key": RAW_KEY}

        first_report = client.get(
            f"/api/v1/assets/{uploaded['omni_id']}/report", headers=headers
        )
        assert first_report.status_code == 200, first_report.text
        body = first_report.json()
        assert body["creator_name"] == "Exact Creator"
        assert body["copyright_owner"] == "Exact Rights LLC"
        assert body["license_type"] == "Exact Custom License"
        assert body["ai_disclosure"] == "ai_assisted"
        assert body["ai_assisted_contributions"]["ai_tools_used"] == ["Exact Tool"]
        assert body["total_verifications"] == 0

        facts = body["stored_facts"]
        assert facts["rights"]["copyright_owner"] == "Exact Rights LLC"
        assert facts["rights"]["ownership_total_pct"] == 100.0
        assert facts["rights"]["ownership_splits"][0]["creative_contribution_pct"] == 0.0
        assert facts["rights"]["ownership_splits"][0]["ai_assisted_pct"] == 0.0

        second_report = client.get(
            f"/api/v1/assets/{uploaded['omni_id']}/report", headers=headers
        )
        assert second_report.json()["total_verifications"] == 0

        verified = client.get(f"/api/v1/verify/{uploaded['omni_id']}")
        assert verified.status_code == 200, verified.text
        assert verified.json()["total_verifications"] == 1

        after_verify = client.get(
            f"/api/v1/assets/{uploaded['omni_id']}/report", headers=headers
        )
        assert after_verify.json()["total_verifications"] == 1

        copyright_report = client.get(
            f"/api/v1/assets/{uploaded['omni_id']}/copyright-report",
            headers=headers,
        )
        rights = copyright_report.json()["ownership_declarations"]
        assert rights["copyright_owner"] == "Exact Rights LLC"
        assert rights["ownership_total_pct"] == 100.0
        assert rights["ownership_splits"][0]["creative_contribution_pct"] == 0.0
        assert rights["ownership_splits"][0]["ai_assisted_pct"] == 0.0


def test_export_contains_canonical_stored_facts_snapshot():
    with TestClient(main.app, raise_server_exceptions=False) as client:
        _ensure_client()
        uploaded = _upload(client, {
            "creator_name": "Export Creator",
            "copyright_owner": "Export Rights LLC",
            "license_type": "Export License",
            "ai_disclosure": "human",
            "ai_disclosure_complete": True,
        })

        response = client.get(
            f"/api/v1/assets/{uploaded['omni_id']}/export",
            headers={"X-API-Key": RAW_KEY},
        )
        assert response.status_code == 200, response.text
        with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
            fact_name = next(name for name in archive.namelist() if name.endswith("stored_facts.json"))
            facts = json.loads(archive.read(fact_name))
            assert facts["identity"]["creator_name"] == "Export Creator"
            assert facts["rights"]["copyright_owner"] == "Export Rights LLC"
            assert facts["rights"]["license_type"] == "Export License"
            assert facts["ai"]["disclosure"] == "human"


def test_list_counts_report_total_separately_from_returned_page():
    with TestClient(main.app, raise_server_exceptions=False) as client:
        _ensure_client()
        _upload(client, {"creator_name": "Count One"})
        _upload(client, {"creator_name": "Count Two"})

        response = client.get(
            "/api/v1/assets?limit=1",
            headers={"X-API-Key": RAW_KEY},
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["returned_count"] == 1
        assert body["total"] == body["total_count"]
        assert body["total_count"] >= 2


def test_hash_verification_never_picks_arbitrary_tenant_for_same_file():
    with TestClient(main.app, raise_server_exceptions=False) as client:
        _ensure_client()
        _ensure_client(
            OTHER_KEY,
            OTHER_TENANT_ID,
            "ingest-evidence-truth-other@example.com",
        )
        shared = _png_bytes()
        first = _upload_bytes(
            client,
            RAW_KEY,
            {"creator_name": "First Tenant Creator"},
            shared,
        )
        second = _upload_bytes(
            client,
            OTHER_KEY,
            {"creator_name": "Second Tenant Creator"},
            shared,
        )
        assert first["omni_id"] != second["omni_id"]
        assert first["sha256"] == second["sha256"]

        response = client.post("/api/v1/verify/hash", json={"sha256": first["sha256"]})
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["verified"] is True
        assert body["ambiguous"] is True
        assert body["match_count"] >= 2
        assert "omni_id" not in body
        ids = {item["omni_id"] for item in body["matches"]}
        assert first["omni_id"] in ids
        assert second["omni_id"] in ids
