from fastapi import APIRouter, UploadFile, File, Form, Depends, HTTPException
from sqlalchemy.orm import Session
from datetime import datetime
import json, os, uuid, logging

from app.core.tenant import resolve_tenant
from app.core.config import settings
from app.utils.hashing import sha256_bytes, blake3_bytes, phash_image, generate_omni_id
from app.utils.watermark import apply_visible_watermark, apply_invisible_watermark
from app.utils.metadata import extract_metadata
from app.utils.upload_limits import read_upload_limited
from app.services.metadata_extraction import extract_metadata_service
from app.services.metadata_persistence import (
    persist_asset_metadata,
    persist_anomaly_score,
    split_layers,
)
from app.utils.security import hash_event, sign_certificate as legacy_hmac_sign_certificate, compute_manifest_hash
from app.services.crypto_signing import get_or_create_dev_trust_keypair, sign_certificate as ed25519_sign_certificate
from app.services.trust import TrustSignals, compute_trust_score
from app.services.copyright_readiness import AuthorshipSignals, compute_copyright_readiness
from app.services.certificate import CertificateContext, build_certificate
from app.utils import hive
from app.db import (
    get_db,
    save_asset,
    ProvenanceEvent,
    Certificate,
    Contributor,
    LiveSplitSession,
)
from app.db.models import Client

router = APIRouter()

logger = logging.getLogger("omniveil.ingest")

ORIGINALS_DIR = "uploads/originals"
WATERMARKED_DIR = "uploads/watermarked"
CERTIFICATES_DIR = "uploads/certificates"
MANIFESTS_DIR = "uploads/manifests"

# Ensure Render/local upload directories exist before writing files.
for _dir in (ORIGINALS_DIR, WATERMARKED_DIR, CERTIFICATES_DIR, MANIFESTS_DIR):
    os.makedirs(_dir, exist_ok=True)

if settings.hive_api_key:
    hive.set_key(settings.hive_api_key)
if settings.sightengine_user and settings.sightengine_secret:
    hive.set_sightengine(settings.sightengine_user, settings.sightengine_secret)


def _provenance_event(omni_id, event_type, description, tool_used, actor, now):
    event_id = str(uuid.uuid4())
    event_data = {
        "event_id": event_id,
        "omni_id": omni_id,
        "event_type": event_type,
        "description": description,
        "tool_used": tool_used,
        "human_or_ai": "system",
        "actor_name": actor,
        "timestamp": now.isoformat(),
    }
    return ProvenanceEvent(
        event_id=event_id,
        omni_id=omni_id,
        event_type=event_type,
        description=description,
        tool_used=tool_used,
        human_or_ai="system",
        actor_name=actor,
        timestamp=now,
        event_hash=hash_event(event_data),
    )


@router.post("/upload")
async def ingest_upload(
    file: UploadFile = File(...),
    provenance_json: str = Form(default="{}"),
    options_json: str = Form(default="{}"),
    tenant: Client = Depends(resolve_tenant),
    db: Session = Depends(get_db),
):
    data = await read_upload_limited(file, max_mb=settings.max_upload_mb)

    try:
        provenance = json.loads(provenance_json or "{}")
        options = json.loads(options_json or "{}")
    except json.JSONDecodeError as exc:
        raise HTTPException(400, f"Invalid JSON form data: {exc.msg}") from exc

    if not isinstance(provenance, dict) or not isinstance(options, dict):
        raise HTTPException(400, "provenance_json and options_json must be JSON objects")

    # ── Step 2: Hashes ──────────────────────────────────────────────────────
    sha256 = sha256_bytes(data)
    b3 = blake3_bytes(data)

    # ── Step 3: Metadata + pHash ────────────────────────────────────────────
    mime_type = file.content_type or "application/octet-stream"
    meta = extract_metadata(data, mime_type)
    exif = meta.get("exif", {})

    ph = None
    if mime_type.startswith("image/"):
        ph = phash_image(data)

    # ── Step 4: Omni ID ─────────────────────────────────────────────────────
    omni_id = generate_omni_id(tenant.tenant_id, sha256)
    asset_id = str(uuid.uuid4())
    now = datetime.utcnow()

    ext = os.path.splitext(file.filename or "file")[1] or ".bin"
    original_filename = file.filename or f"file{ext}"

    # ── Step 1: Save original ───────────────────────────────────────────────
    original_path = os.path.join(ORIGINALS_DIR, f"{omni_id}{ext}")
    with open(original_path, "wb") as f:
        f.write(data)

    # ── AI detection ────────────────────────────────────────────────────────
    ai_score = None
    if mime_type.startswith("image/"):
        try:
            ai_score = await hive.detect_ai_image(data, mime_type)
        except Exception:
            ai_score = None
    elif mime_type.startswith("audio/"):
        try:
            ai_score = await hive.detect_ai_audio(data)
        except Exception:
            ai_score = None

    # ── Watermarking ────────────────────────────────────────────────────────
    watermarked = data
    wm_visible = False
    wm_invisible = False

    if options.get("visible_watermark", True) and mime_type.startswith("image/"):
        watermarked = apply_visible_watermark(watermarked, "OMNI VEIL")
        wm_visible = True

    if options.get("invisible_watermark", True) and mime_type.startswith("image/"):
        watermarked = apply_invisible_watermark(watermarked, omni_id[:32])
        wm_invisible = True

    watermarked_path = None
    if wm_visible or wm_invisible:
        watermarked_path = os.path.join(WATERMARKED_DIR, f"{omni_id}{ext}")
        with open(watermarked_path, "wb") as f:
            f.write(watermarked)

    # ── Extract human authorship + copyright readiness fields from provenance ──
    human_creative_direction   = provenance.get("human_creative_direction")
    human_editing_present      = provenance.get("human_editing_present")
    human_arrangement_present  = provenance.get("human_arrangement_present")
    human_lyrics_present       = provenance.get("human_lyrics_present")
    human_performance_present  = provenance.get("human_performance_present")
    human_transformation_present = provenance.get("human_transformation_present")
    ai_disclosure_complete     = provenance.get("ai_disclosure_complete")
    ai_tools_used              = provenance.get("ai_tools_used") or []  # list[str]
    ai_modification_by_human   = provenance.get("ai_modification_by_human")
    human_authorship_summary   = provenance.get("human_authorship_summary")
    contributor_count          = provenance.get("contributor_count")    # int | None

    # ── Trust score ─────────────────────────────────────────────────────────
    human_contribution_count = sum([
        bool(human_arrangement_present),
        bool(human_editing_present),
        bool(human_lyrics_present),
        bool(human_performance_present),
        bool(human_transformation_present),
        bool(provenance.get("human_drums_added")),
        bool(provenance.get("human_chords_added")),
        bool(provenance.get("human_mix_master")),
    ]) or None

    signals = TrustSignals(
        has_exif=bool(exif),
        has_gps=bool(exif.get("GPS GPSLatitude")),
        has_creator_name=bool(provenance.get("creator_name")),
        has_creator_org=bool(provenance.get("creator_org")),
        has_copyright=bool(provenance.get("copyright_notice")),
        has_license_url=bool(provenance.get("license_url")),
        is_ai_generated=provenance.get("is_ai_generated"),
        is_ai_disclosed=provenance.get("is_ai_generated") is not None,
        ai_detection_score=ai_score,
        invisible_wm_verified=True if wm_invisible else None,
        invisible_wm_confidence=1.0 if wm_invisible else None,
        transformation_level=provenance.get("transformation_level"),
        human_contribution_count=human_contribution_count,
        has_daw=bool(provenance.get("daw_used")),
    )
    trust = compute_trust_score(signals)

    # ── Live Split / contributor metadata from provenance ─────────────────────
    live_split = provenance.get("live_split") or {}
    if not isinstance(live_split, dict):
        raise HTTPException(400, "live_split must be a JSON object")
    contributors = live_split.get("contributors") or provenance.get("contributors") or []
    section_c_ownership_splits = provenance.get("section_c_ownership_splits") or {}

    if not isinstance(contributors, list):
        raise HTTPException(400, "contributors must be a JSON array")

    normalized_contributors = []
    for index, contributor in enumerate(contributors, start=1):
        if not isinstance(contributor, dict):
            raise HTTPException(400, f"Contributor {index} must be a JSON object")

        name = str(
            contributor.get("name") or contributor.get("contributor_name") or ""
        ).strip()
        if not name:
            raise HTTPException(400, f"Contributor {index} requires a name")

        def _percentage(key: str, fallback: str | None = None):
            value = contributor.get(key)
            if value is None and fallback:
                value = contributor.get(fallback)
            if value in (None, ""):
                return None
            try:
                number = float(value)
            except (TypeError, ValueError) as exc:
                raise HTTPException(
                    400, f"Contributor {index} has an invalid {key}"
                ) from exc
            if number < 0 or number > 100:
                raise HTTPException(400, f"Contributor {index} {key} must be 0-100")
            return number

        normalized_contributors.append({
            **contributor,
            "name": name,
            "role": str(contributor.get("role") or "Contributor").strip(),
            "contribution_type": contributor.get("contribution_type") or (
                "ai" if contributor.get("isAI") else "human"
            ),
            "creative_contribution_pct": _percentage("creative_contribution_pct"),
            "ownership_split_pct": _percentage(
                "ownership_split_pct", "split_percentage"
            ),
            "ai_assisted_pct": _percentage("ai_assisted_pct"),
        })

    contributors = normalized_contributors

    if contributors:
        declared_ownership = [
            contributor["ownership_split_pct"]
            for contributor in contributors
            if contributor["ownership_split_pct"] is not None
        ]
        if len(declared_ownership) != len(contributors):
            raise HTTPException(400, "Every contributor requires an ownership split")
        if abs(sum(declared_ownership) - 100.0) > 0.01:
            raise HTTPException(400, "Contributor ownership splits must total 100%")

    if contributors and contributor_count is None:
        contributor_count = len(contributors)

    # ── Copyright readiness score ────────────────────────────────────────────
    cr_signals = AuthorshipSignals(
        human_creative_direction=human_creative_direction,
        human_editing_present=human_editing_present,
        human_arrangement_present=human_arrangement_present,
        human_lyrics_present=human_lyrics_present,
        human_performance_present=human_performance_present,
        human_transformation_present=human_transformation_present,
        ai_disclosure_complete=ai_disclosure_complete,
        ai_tools_used=ai_tools_used,
        ai_modification_by_human=ai_modification_by_human,
        ai_detection_score=ai_score,
        is_ai_disclosed=provenance.get("is_ai_generated") is not None,
        human_contributor_count=contributor_count,
    )
    cr = compute_copyright_readiness(cr_signals)

    if provenance.get("is_ai_generated") is True:
        ai_disclosure = "ai"
    elif provenance.get("is_ai_generated") is False:
        ai_disclosure = "human"
    else:
        ai_disclosure = None

    creator_name = provenance.get("creator_name")
    copyright_owner = provenance.get("copyright_owner") or creator_name
    license_type = provenance.get("license_type")

    # ── Step 6: Build + sign certificate ────────────────────────────────────
    cert_id = str(uuid.uuid4())
    cert_ctx = CertificateContext(
        cert_id=cert_id,
        omni_id=omni_id,
        asset_id=asset_id,
        issued_at=now.isoformat(),
        filename=original_filename,
        sha256=sha256,
        blake3=b3,
        trust_score=trust.score,
        content_label=trust.label,
        copyright_readiness=cr,
        creator_name=creator_name,
        copyright_owner=copyright_owner,
        license_type=license_type,
        ai_disclosure=ai_disclosure,
        human_creative_direction=human_creative_direction,
        human_editing_present=human_editing_present,
        human_arrangement_present=human_arrangement_present,
        human_lyrics_present=human_lyrics_present,
        human_performance_present=human_performance_present,
        human_transformation_present=human_transformation_present,
        human_authorship_summary=human_authorship_summary,
        ai_tools_used=ai_tools_used,
        ai_disclosure_complete=ai_disclosure_complete,
        ai_modification_by_human=ai_modification_by_human,
        ai_detection_score=ai_score,
        contributors=contributors,
    )
    cert_payload = build_certificate(cert_ctx)

    certificate_metadata_lock = {
        "omni_id": omni_id,
        "asset_id": asset_id,
        "filename": original_filename,
        "file_type": mime_type,
        "file_size_bytes": len(data),
        "sha256": sha256,
        "blake3": b3,
        "phash": ph,
        "creator_name": creator_name,
        "copyright_owner": copyright_owner,
        "license_type": license_type,
        "ai_disclosure": ai_disclosure,
        "contributors": contributors,
        "created_at": now.isoformat(),
    }

    # Development Trust Authority keypair.
    # Production must use OV private keys from AWS KMS / Secrets Manager / offline vault.
    trust_keys = get_or_create_dev_trust_keypair()

    signed_cert_payload = ed25519_sign_certificate(
        certificate=cert_payload,
        metadata=certificate_metadata_lock,
        private_key_b64=trust_keys["private_key_b64"],
        public_key_b64=trust_keys["public_key_b64"],
        public_key_id="OV-ROOT-DEV-001",
    )

    signed_cert_payload["metadata_lock"] = certificate_metadata_lock
    signed_cert_payload["legacy_hmac_signature"] = legacy_hmac_sign_certificate(cert_payload)

    cert_payload = signed_cert_payload
    cert_json_str = json.dumps(cert_payload, indent=2)
    cert_hash = sha256_bytes(cert_json_str.encode())

    certificate_path = os.path.join(CERTIFICATES_DIR, f"{omni_id}.json")
    with open(certificate_path, "w") as f:
        f.write(cert_json_str)

    # ── Step 7: Build + write provenance manifest ────────────────────────────
    registry_url = f"https://omniveil-backend.onrender.com/api/v1/registry/assets/{omni_id}"
    manifest = {
        "manifest_version": "1.1",
        "omni_id": omni_id,
        "asset_id": asset_id,
        "filename": original_filename,
        "file_type": mime_type,
        "file_size_bytes": len(data),
        "sha256": sha256,
        "blake3": b3,
        "phash": ph,
        "trust_score": trust.score,
        "content_label": trust.label,
        "creator_name": creator_name,
        "copyright_owner": copyright_owner,
        "license_type": license_type,
        "ai_disclosure": ai_disclosure,
        "live_split": live_split,
        "contributors": contributors,
        "section_c_ownership_splits": section_c_ownership_splits,
        "watermark_applied": wm_visible or wm_invisible,
        "watermark_visible": wm_visible,
        "watermark_invisible": wm_invisible,
        "original_path": original_path,
        "watermarked_path": watermarked_path,
        "certificate_path": certificate_path,
        "created_at": now.isoformat(),
        "registry_url": registry_url,
        # ── Creative provenance documentation ────────────────────────────────
        "certificate_class": cert_payload["certificate_class"],
        "certificate_class_label": cert_payload["certificate_class_label"],
        "copyright_readiness_score": cr.score,
        "copyright_readiness_label": cr.label,
        "section_a_human_contributions": cert_payload["section_a_human_contributions"],
        "section_b_ai_contributions": cert_payload["section_b_ai_contributions"],
        "section_c_ownership_splits": cert_payload["section_c_ownership_splits"],
        "authorship_support_factors": {
            "supporting": cr.factors_supporting,
            "limiting": cr.factors_limiting,
        },
        "legal_disclaimer": cr.legal_disclaimer,
    }
    manifest["manifest_hash"] = compute_manifest_hash(manifest)

    manifest_path = os.path.join(MANIFESTS_DIR, f"{omni_id}.json")
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)

    # ── Step 5: Save asset to DB ─────────────────────────────────────────────
    save_asset(db, {
        "omni_id": omni_id,
        "asset_id": asset_id,
        "tenant_id": tenant.tenant_id,
        "filename": original_filename,
        "mime_type": mime_type,
        "original_path": original_path,
        "watermarked_path": watermarked_path,
        "certificate_path": certificate_path,
        "manifest_path": manifest_path,
        "sha256": sha256,
        "blake3": b3,
        "phash": ph,
        "trust_score": trust.score,
        "content_label": trust.label,
        "label_reasons": trust.reasons,
        "ai_detection_score": ai_score,
        "ai_disclosure": ai_disclosure,
        "watermark_applied": wm_visible or wm_invisible,
        "watermark_visible": wm_visible,
        "watermark_invisible": wm_invisible,
        "asset_type": mime_type.split("/")[0] if "/" in mime_type else "file",
        "file_size_bytes": len(data),
        "creator_name": creator_name,
        "copyright_owner": copyright_owner,
        "license_type": license_type,
        "registry_url": registry_url,
        "metadata_json": json.dumps(meta),
        # ── Human authorship evidence ────────────────────────────────────────
        "human_creative_direction": human_creative_direction,
        "human_editing_present": human_editing_present,
        "human_arrangement_present": human_arrangement_present,
        "human_lyrics_present": human_lyrics_present,
        "human_performance_present": human_performance_present,
        "human_transformation_present": human_transformation_present,
        # ── Copyright readiness ──────────────────────────────────────────────
        "copyright_readiness_score": cr.score,
        "copyright_readiness_label": cr.label,
        "certificate_class": cr.certificate_class,
        "certificate_class_label": cert_payload["certificate_class_label"],
        "ai_disclosure_complete": ai_disclosure_complete,
        "ai_tools_used_json": json.dumps(ai_tools_used) if ai_tools_used else None,
        "ai_modification_by_human": ai_modification_by_human,
        "human_authorship_summary": human_authorship_summary,
    })

    # ── Step 6: Certificate DB record ────────────────────────────────────────
    db.add(Certificate(
        cert_id=cert_id,
        omni_id=omni_id,
        certificate_hash=cert_hash,
        issued_at=now,
        issuer="Omni Veil Trust OS",
        subject_name=creator_name or "Unknown",
        certificate_class=cr.certificate_class,
        cert_json=cert_json_str,
        signature=cert_payload["signature"],
    ))

    for contributor in contributors:
        db.add(Contributor(
            contributor_id=str(uuid.uuid4()),
            omni_id=omni_id,
            contributor_name=contributor["name"],
            role=contributor["role"],
            contribution_type=contributor["contribution_type"],
            split_percentage=contributor["ownership_split_pct"],
            creative_contribution_pct=contributor["creative_contribution_pct"],
            ownership_split_pct=contributor["ownership_split_pct"],
            ai_assisted_pct=contributor["ai_assisted_pct"],
            wallet_address=contributor.get("wallet_address"),
        ))

    if live_split:
        contributors_json = json.dumps(contributors, sort_keys=True)
        db.add(LiveSplitSession(
            session_id=str(uuid.uuid4()),
            omni_id=omni_id,
            tenant_id=tenant.tenant_id,
            session_name=str(
                live_split.get("session_name")
                or provenance.get("asset_title")
                or original_filename
            ),
            status="locked",
            contributors_json=contributors_json,
            created_at=now,
            locked_at=now,
            session_hash=sha256_bytes(contributors_json.encode()),
        ))

    # ── Provenance events (immutable audit trail) ────────────────────────────
    actor = creator_name or "system"
    db.add(_provenance_event(
        omni_id, "upload",
        f"Original file ingested: {original_filename} ({len(data)} bytes)",
        "Omni Veil Ingest API", actor, now,
    ))
    if wm_visible or wm_invisible:
        wm_types = ", ".join(filter(None, [
            "visible" if wm_visible else None,
            "invisible" if wm_invisible else None,
        ]))
        db.add(_provenance_event(
            omni_id, "watermark",
            f"Watermark applied ({wm_types})",
            "Omni Veil Watermark Engine", "system", now,
        ))
    db.add(_provenance_event(
        omni_id, "certificate_issued",
        f"Provenance certificate signed and issued (cert_id={cert_id})",
        "Omni Veil Trust OS", "system", now,
    ))

    db.commit()

    # ── Metadata Intelligence Commit 2: persist normalized extraction ─────────
    # Runs AFTER the asset is durably committed so a metadata-persistence failure
    # can never roll back or fail the upload. Extraction-only inputs; no change
    # to the upload response shape, Live Split, certificates, registry or verify.
    try:
        extraction = extract_metadata_service(
            data, filename=original_filename, mime_type=mime_type
        )
        record = persist_asset_metadata(
            db,
            asset_id=asset_id,
            tenant_id=tenant.tenant_id,
            omni_id=omni_id,
            extraction=extraction,
        )
        # Commit 4: compute + persist the deterministic anomaly score from the
        # layers we just persisted. Runs after persistence so an anomaly failure
        # can never roll back the metadata or the upload; the upload response
        # shape is unchanged (anomaly data is served by the /anomalies endpoint).
        raw, normalized, derived = split_layers(extraction)
        persist_anomaly_score(
            db, record,
            raw=raw, normalized=normalized, derived=derived,
            mime_type=mime_type,
        )
    except Exception as exc:  # never break the upload on metadata persistence
        logger.warning(
            "Metadata persistence skipped for omni_id=%s: %s", omni_id, exc
        )

    return {
        "omni_id": omni_id,
        "asset_id": asset_id,
        "cert_id": cert_id,
        "filename": original_filename,
        "sha256": sha256,
        "blake3": b3,
        "phash": ph,
        "trust_score": trust.score,
        "content_label": trust.label,
        "label_reasons": trust.reasons,
        "ai_detection_score": ai_score,
        "ai_disclosure": ai_disclosure,
        "watermark_applied": wm_visible or wm_invisible,
        "watermark_visible": wm_visible,
        "watermark_invisible": wm_invisible,
        "creator_name": creator_name,
        "copyright_owner": copyright_owner,
        "license_type": license_type,
        "original_path": original_path,
        "watermarked_path": watermarked_path,
        "certificate_path": certificate_path,
        "manifest_path": manifest_path,
        "registry_url": registry_url,
        "created_at": now.isoformat(),
        "mime_type": mime_type,
        "asset_type": mime_type.split("/")[0] if "/" in mime_type else "file",
        "file_size_bytes": len(data),
        # ── Copyright readiness ──────────────────────────────────────────────
        "certificate_class": cert_payload["certificate_class"],
        "certificate_class_label": cert_payload["certificate_class_label"],
        "copyright_readiness": cert_payload["copyright_readiness"],
        "section_a_human_contributions": cert_payload["section_a_human_contributions"],
        "section_b_ai_contributions": cert_payload["section_b_ai_contributions"],
        "section_c_ownership_splits": cert_payload["section_c_ownership_splits"],
        "legal_disclaimer": cert_payload["legal_disclaimer"],
    }