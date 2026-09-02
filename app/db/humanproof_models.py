from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import relationship

from app.db.base import Base


class HumanProofSession(Base):
    __tablename__ = "humanproof_sessions"

    session_id = Column(String, primary_key=True, index=True)
    tenant_id = Column(String, nullable=False, index=True)
    omni_id = Column(String, ForeignKey("assets.omni_id"), nullable=True, index=True)
    status = Column(String, nullable=False, default="recording", index=True)
    schema_version = Column(String, nullable=False, default="1.0")
    current_hash = Column(String, nullable=True)
    created_by = Column(String, nullable=True)
    started_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    closed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    events = relationship(
        "HumanProofEvent",
        back_populates="session",
        cascade="all, delete-orphan",
        order_by="HumanProofEvent.sequence",
    )


class HumanProofEvent(Base):
    __tablename__ = "humanproof_events"
    __table_args__ = (
        UniqueConstraint("session_id", "sequence", name="uq_humanproof_session_sequence"),
    )

    event_id = Column(String, primary_key=True, index=True)
    session_id = Column(
        String,
        ForeignKey("humanproof_sessions.session_id"),
        nullable=False,
        index=True,
    )
    tenant_id = Column(String, nullable=False, index=True)
    omni_id = Column(String, ForeignKey("assets.omni_id"), nullable=True, index=True)
    sequence = Column(Integer, nullable=False)
    event_type = Column(String, nullable=False, index=True)
    occurred_at = Column(DateTime, nullable=False)
    recorded_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    evidence_hash = Column(String, nullable=False, index=True)
    previous_event_hash = Column(String, nullable=True)
    source_type = Column(String, nullable=False)
    source_name = Column(String, nullable=True)
    creator_id = Column(String, nullable=True)
    ai_disclosure_json = Column(Text, nullable=True)
    location_json = Column(Text, nullable=True)
    payload_json = Column(Text, nullable=False, default="{}")
    schema_version = Column(String, nullable=False, default="1.0")

    session = relationship("HumanProofSession", back_populates="events")
