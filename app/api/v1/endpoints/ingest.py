from fastapi import APIRouter, UploadFile, File, Form, Depends, HTTPException
from sqlalchemy.orm import Session
from datetime import datetime
import json, os, uuid

from app.core.tenant import resolve_tenant
from app.core.config import settings
from app.utils.hashing import sha256_bytes, blake3_bytes, phash_image, generate_omni_id
from app.utils.watermark import apply_visible_watermark, apply_invisible_watermark
from app.utils.metadata import extract_metadata
from app.utils.security import hash_event, sign_certificate, compute_manifest_hash
from app.services.trust import TrustSignals, compute_trust_score
from app.services.copyright_readiness import AuthorshipSignals, compute_copyright_readiness
from app.services.certificate import CertificateContext, build_certificate
from app.utils import hive
from app.db import get_db, save_asset, ProvenanceEvent, Certificate
from app.db.models import Client

router = APIRouter()

ORIGINALS_DIR = "uploads/originals"
WATERMARKED_DIR = "uploads/watermarked"
CERTIFICATES_DIR = "uploads/certificates"
MANIFESTS_DIR = "uploads/manifests"

hive.set_key(settings.omni_api_key)
hive.set_sightengine("1158794285", "7NBWjGaZYhTfbV6S4dawgLJxHZMu2ytA")


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
    data = await file.read()
    if len(data) > settings.max_upload_mb * 1024 * 1024:
        raise HTTPException(413, "File too large")

    provenance = json.loads(provenance_json or "{}")
    options = json.loads(options_json or "{}")

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
        contributors=[],   # contributor rows added in step 4 (live-split endpoint)
    )
    cert_payload = build_certificate(cert_ctx)
    sig = sign_certificate(cert_payload)
    cert_payload["signature"] = sig
    cert_json_str = json.dumps(cert_payload, indent=2)
    cert_hash = sha256_bytes(cert_json_str.encode())

    certificate_path = os.path.join(CERTIFICATES_DIR, f"{omni_id}.json")
    with open(certificate_path, "w") as f:
        f.write(cert_json_str)

    # ── Step 7: Build + write provenance manifest ────────────────────────────
    registry_url = f"http://localhost:8000/api/v1/registry/assets/{omni_id}"
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
        signature=sig,
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

    return {
        "omni_id": omni_id,
        "asset_id": asset_id,
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
