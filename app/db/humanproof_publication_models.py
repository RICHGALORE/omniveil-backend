from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, String, Text

from app.db.base import Base


class HumanProofPublication(Base):
    """Mutable creator publication preferences, separate from the evidence chain."""

    __tablename__ = "humanproof_publications"

    session_id = Column(
        String,
        ForeignKey("humanproof_sessions.session_id"),
        primary_key=True,
    )
    tenant_id = Column(String, nullable=False, index=True)
    omni_id = Column(String, nullable=False, index=True)
    fields_json = Column(Text, nullable=False, default="[]")
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
