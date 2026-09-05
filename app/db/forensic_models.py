from datetime import datetime

from sqlalchemy import Column, DateTime, Float, ForeignKey, String, Text

from app.db.base import Base


class ForensicObservation(Base):
    """Append-only provider-specific forensic evidence about a registered asset.

    Each row preserves who produced the observation, which model/signal it came
    from, and the probability observed at that time. Provider scores are never
    collapsed into a shared database field.
    """

    __tablename__ = "forensic_observations"

    observation_id = Column(String, primary_key=True, index=True)
    omni_id = Column(String, ForeignKey("assets.omni_id"), nullable=False, index=True)
    tenant_id = Column(String, nullable=False, index=True)

    provider = Column(String, nullable=False, index=True)
    model = Column(String, nullable=False)
    signal = Column(String, nullable=False, index=True)
    probability = Column(Float, nullable=False)
    status = Column(String, nullable=False, default="available")
    details_json = Column(Text, nullable=True)

    observed_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
