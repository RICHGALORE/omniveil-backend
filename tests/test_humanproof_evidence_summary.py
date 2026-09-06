from app.api.v1.endpoints.humanproof import _public_evidence_summary


def _serialized_record():
    return {
        "events": [
            {
                "event_type": "session_started",
                "source_name": "Logic Pro",
                "payload": {
                    "workflow": "Human Transformation v1",
                    "production_environment": "Logic Pro",
                },
            },
            {
                "event_type": "source_captured",
                "payload": {
                    "checkpoint": "automatic_project_detected",
                    "connected_production_hardware": [
                        {"name": "MPC Key 61", "category": "production_workstation"},
                    ],
                    "process_only_environments": ["Serato DJ Pro"],
                },
            },
            {
                "event_type": "source_captured",
                "payload": {
                    "checkpoint": "source_asset_linked",
                    "source_omni_id": "OV-SOURCE123",
                    "source_ai_disclosure": "ai_generated",
                    "source_ai_detection_score": 0.91,
                    "source_content_label": "synthetic",
                    "history_mutated": False,
                },
            },
            {
                "event_type": "work_saved",
                "payload": {
                    "checkpoint": "automatic_project_revision",
                },
            },
            {
                "event_type": "work_saved",
                "payload": {
                    "checkpoint": "human_transformation_declared",
                    "transformations": ["rearranged", "vocals_replaced"],
                    "statement": "Rebuilt the arrangement and replaced the vocal.",
                },
            },
            {
                "event_type": "work_exported",
                "payload": {"checkpoint": "automatic_audio_export"},
            },
            {
                "event_type": "contributor_declared",
                "payload": {"contributor_name": "Collaborator"},
            },
            {
                "event_type": "ai_tool_disclosed",
                "payload": {"final_provenance_disclosure": "ai_assisted"},
            },
        ]
    }


def test_proof_mode_summary_exposes_values_but_hides_source_omni_id_and_statement():
    summary = _public_evidence_summary(_serialized_record(), "proof")
    assert summary["production_environment"] == "Logic Pro"
    assert summary["connected_production_hardware"] == [
        {"name": "MPC Key 61", "category": "production_workstation"}
    ]
    assert summary["additional_production_apps"] == ["Serato DJ Pro"]
    assert summary["automatic_project_detected"] is True
    assert summary["automatic_revisions"] == 1
    assert summary["automatic_exports"] == 1
    assert summary["contributor_declarations"] == 1

    transformation = summary["human_transformation"]
    assert transformation["verified"] is True
    assert transformation["source_lineage"]["source_ai_disclosure"] == "ai_generated"
    assert transformation["source_lineage"]["source_ai_detection_score"] == 0.91
    assert transformation["source_lineage"]["source_omni_id"] is None
    assert transformation["statement"] is None
    assert transformation["final_provenance_disclosure"] == "ai_assisted"


def test_public_mode_can_show_creator_authorized_source_lineage_and_statement():
    summary = _public_evidence_summary(_serialized_record(), "public")
    transformation = summary["human_transformation"]
    assert transformation["source_lineage"]["source_omni_id"] == "OV-SOURCE123"
    assert transformation["statement"] == "Rebuilt the arrangement and replaced the vocal."
