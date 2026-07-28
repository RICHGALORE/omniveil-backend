from sqlalchemy import (
    Column, String, Float, Boolean, DateTime, Text, Integer, ForeignKey
)
from sqlalchemy.orm import relationship
from datetime import datetime
from app.db.base import Base


class Asset(Base):
    """Primary provenance record for every ingested file."""
    __tablename__ = "assets"

    omni_id = Column(String, primary_key=True, index=True)
    asset_id = Column(String, unique=True, index=True)

    # File identity
    filename = Column(String, nullable=False, default="")
    file_type = Column(String, nullable=False, default="application/octet-stream")
    original_path = Column(String, nullable=False, default="")
    watermarked_path = Column(String, nullable=True)
    certificate_path = Column(String, nullable=True)
    manifest_path = Column(String, nullable=True)

    # Cryptographic fingerprints
    sha256 = Column(String, nullable=False)
    blake3 = Column(String, nullable=False)
    phash = Column(String, nullable=True)

    # Trust & classification
    trust_score = Column(Float, nullable=False, default=0.5)
    content_label = Column(String, nullable=False, default="unverified")
    label_reasons = Column(Text, nullable=True)         # JSON array
    ai_detection_score = Column(Float, nullable=True)

    # Watermark flags
    watermark_applied = Column(Boolean, default=False)
    watermark_visible = Column(Boolean, default=False)
    watermark_invisible = Column(Boolean, default=False)

    # Provenance / ownership
    creator_name = Column(String, nullable=True)
    copyright_owner = Column(String, nullable=True)
    license_type = Column(String, nullable=True)
    ai_disclosure = Column(String, nullable=True)       # "human" | "ai" | "mixed"

    # Supplementary
    asset_type = Column(String, nullable=True)          # "image" | "audio" | "video" | …
    file_size_bytes = Column(Integer, nullable=True)
    total_verifications = Column(Integer, default=0)
    registry_url = Column(String, nullable=True)
    metadata_json = Column(Text, nullable=True)         # full extracted metadata blob

    created_at = Column(DateTime, default=datetime.utcnow)

    # ── Human Authorship Evidence ──────────────────────────────────────────────
    # Documents the specific forms of human creative contribution present.
    # Used by the copyright readiness scoring system.
    human_creative_direction = Column(Boolean, nullable=True)
    human_editing_present = Column(Boolean, nullable=True)
    human_arrangement_present = Column(Boolean, nullable=True)
    human_lyrics_present = Column(Boolean, nullable=True)
    human_performance_present = Column(Boolean, nullable=True)
    human_transformation_present = Column(Boolean, nullable=True)

    # ── Copyright Readiness ────────────────────────────────────────────────────
    # Separate from trust_score: measures strength of documented human authorship
    # evidence. Does not represent legal copyright status or ownership certainty.
    copyright_readiness_score = Column(Float, nullable=True)          # 0.0 – 1.0
    copyright_readiness_label = Column(String, nullable=True)         # strong | moderate | limited | insufficient

    # ── Certificate classification ─────────────────────────────────────────────
    # Columns already created by the additive migration in db/session.py
    # (assets.certificate_class / assets.certificate_class_label). Declared here
    # so the ORM can read them; the public registry endpoint references these.
    certificate_class = Column(String, nullable=True)
    certificate_class_label = Column(String, nullable=True)
    ai_disclosure_complete = Column(Boolean, nullable=True)
    ai_tools_used_json = Column(Text, nullable=True)                  # JSON array of tool names
    ai_modification_by_human = Column(Boolean, nullable=True)
    human_authorship_summary = Column(Text, nullable=True)

    # Relationships
    provenance_events = relationship(
        "ProvenanceEvent", back_populates="asset", cascade="all, delete-orphan"
    )
    certificates = relationship(
        "Certificate", back_populates="asset", cascade="all, delete-orphan"
    )
    contributors = relationship(
        "Contributor", back_populates="asset", cascade="all, delete-orphan"
    )
    verification_logs = relationship(
        "VerificationLog", back_populates="asset", cascade="all, delete-orphan"
    )
    split_sessions = relationship(
        "LiveSplitSession", back_populates="asset"
    )


class ProvenanceEvent(Base):
    """Immutable audit-trail entry for every action taken on an asset."""
    __tablename__ = "provenance_events"

    event_id = Column(String, primary_key=True, index=True)
    omni_id = Column(String, ForeignKey("assets.omni_id"), nullable=False, index=True)

    event_type = Column(String, nullable=False)         # "upload" | "watermark" | "verify" | "certificate" | …
    description = Column(Text, nullable=True)
    tool_used = Column(String, nullable=True)
    human_or_ai = Column(String, nullable=False, default="system")  # "human" | "ai" | "system"
    actor_name = Column(String, nullable=True)

    timestamp = Column(DateTime, default=datetime.utcnow)

    # SHA-256 of this row's content — detects tampering
    event_hash = Column(String, nullable=False)

    asset = relationship("Asset", back_populates="provenance_events")


class Certificate(Base):
    """Signed provenance certificate issued at upload time."""
    __tablename__ = "certificates"

    cert_id = Column(String, primary_key=True, index=True)
    omni_id = Column(String, ForeignKey("assets.omni_id"), nullable=False, index=True)

    certificate_hash = Column(String, nullable=False)   # SHA-256 of cert_json
    issued_at = Column(DateTime, default=datetime.utcnow)
    issuer = Column(String, nullable=False, default="Omni Veil Trust OS")
    subject_name = Column(String, nullable=True)

    # standard | hybrid_authorship | live_split | ai_assisted
    certificate_class = Column(String, nullable=True, default="standard")

    cert_json = Column(Text, nullable=False)            # full certificate JSON blob
    signature = Column(String, nullable=False)          # HMAC-SHA256 of cert_json

    asset = relationship("Asset", back_populates="certificates")


class Contributor(Base):
    """Human or AI contributor credited on an asset."""
    __tablename__ = "contributors"

    contributor_id = Column(String, primary_key=True, index=True)
    omni_id = Column(String, ForeignKey("assets.omni_id"), nullable=False, index=True)

    contributor_name = Column(String, nullable=False)
    role = Column(String, nullable=True)                # "artist" | "producer" | "engineer" | …
    contribution_type = Column(String, nullable=False, default="human")  # "human" | "ai"
    split_percentage = Column(Float, nullable=True)     # legacy — maps to ownership_split_pct
    wallet_address = Column(String, nullable=True)

    # ── Live-split three-column model ─────────────────────────────────────────
    creative_contribution_pct = Column(Float, nullable=True)  # what this contributor created
    ownership_split_pct = Column(Float, nullable=True)        # legal ownership share
    ai_assisted_pct = Column(Float, nullable=True)            # portion assisted by AI tools

    added_at = Column(DateTime, default=datetime.utcnow)

    asset = relationship("Asset", back_populates="contributors")


class LiveSplitSession(Base):
    """Live attribution / split-sheet session, optionally linked to an asset."""
    __tablename__ = "live_split_sessions"

    session_id = Column(String, primary_key=True, index=True)
    omni_id = Column(String, ForeignKey("assets.omni_id"), nullable=True, index=True)

    session_name = Column(String, nullable=False)
    status = Column(String, nullable=False, default="open")  # "open" | "locked" | "finalized"

    contributors_json = Column(Text, nullable=True)     # JSON array of {name, role, split}
    created_at = Column(DateTime, default=datetime.utcnow)
    locked_at = Column(DateTime, nullable=True)

    # SHA-256 of contributors_json at lock time — immutable once set
    session_hash = Column(String, nullable=True)

    asset = relationship("Asset", back_populates="split_sessions")


class VerificationLog(Base):
    """Append-only log of every verification check performed."""
    __tablename__ = "verification_logs"

    log_id = Column(String, primary_key=True, index=True)
    omni_id = Column(String, ForeignKey("assets.omni_id"), nullable=True, index=True)

    check_type = Column(String, nullable=False)         # "file_hash" | "omni_id" | "manifest" | "certificate"
    result = Column(String, nullable=False)             # "pass" | "fail" | "warning"
    details_json = Column(Text, nullable=True)          # JSON object with check details
    verified_by = Column(String, nullable=True)         # IP address or user identifier

    timestamp = Column(DateTime, default=datetime.utcnow)

    # SHA-256 of this row's content — preserves audit trail integrity
    log_hash = Column(String, nullable=False)

    asset = relationship("Asset", back_populates="verification_logs")


class AssetMetadata(Base):
    """
    Durable, per-asset metadata record produced by the Metadata Intelligence
    engine (Commit 2 — persistence only).

    One primary record per asset. Three JSON layers are stored side-by-side:
      * raw_metadata_json        — exact extractor output where practical
      * normalized_metadata_json — canonical Omni Veil sections
      * derived_metadata_json    — values computed by Omni Veil (engine identity,
                                    extractor flags, warnings, timing, sha256)

    This table does not modify or replace the legacy ``assets.metadata_json``
    blob; it is an additional dedicated persistence layer.
    """
    __tablename__ = "asset_metadata"

    id = Column(String, primary_key=True, index=True)

    # Asset linkage. asset_id is unique -> enforces one metadata record per asset.
    asset_id = Column(
        String, ForeignKey("assets.asset_id"), unique=True, index=True, nullable=False
    )
    omni_id = Column(String, ForeignKey("assets.omni_id"), index=True, nullable=True)
    tenant_id = Column(String, index=True, nullable=True)

    # Engine identity (stamped from central constants).
    engine_name = Column(String, nullable=True)
    engine_version = Column(String, nullable=True)

    # Extractor envelope.
    extractor = Column(String, nullable=True)
    exiftool_available = Column(Boolean, nullable=True)
    supported = Column(Boolean, nullable=True)

    # Three durable JSON layers.
    raw_metadata_json = Column(Text, nullable=True)
    normalized_metadata_json = Column(Text, nullable=True)
    derived_metadata_json = Column(Text, nullable=True)
    warnings_json = Column(Text, nullable=True)

    # Deterministic SHA-256 over the canonical normalized metadata.
    metadata_sha256 = Column(String, index=True, nullable=True)

    extraction_duration_ms = Column(Float, nullable=True)

    analyzed_at = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class Client(Base):
    """
    Registered tenant / API client.
    API keys are never stored in plaintext — only the SHA-256 hash is kept.
    """
    __tablename__ = "clients"

    id = Column(String, primary_key=True, index=True)
    tenant_id = Column(String, unique=True, index=True, nullable=False)

    # Company / contact
    company_name = Column(String, nullable=False)
    contact_name = Column(String, nullable=True)
    email = Column(String, unique=True, index=True, nullable=False)
    phone = Column(String, nullable=True)
    industry = Column(String, nullable=True)
    intended_use = Column(Text, nullable=True)
    website = Column(String, nullable=True)

    # Lifecycle
    status = Column(String, nullable=False, default="pending")    # pending | approved | suspended
    plan = Column(String, nullable=False, default="creator")      # founder | creator | label | enterprise

    # Auth — raw key shown once at approval, never stored
    api_key_hash = Column(String, nullable=True, index=True)

    created_at = Column(DateTime, default=datetime.utcnow)
    approved_at = Column(DateTime, nullable=True)
