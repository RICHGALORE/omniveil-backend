from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, String, Text

from app.db.base import Base


class DigitalProductPassport(Base):
    """Tenant-scoped item-level Digital Product Passport readiness record.

    This record binds an Omni asset identity to optional standards-backed product
    identifiers. It is a readiness/provenance record, not a legal or regulatory
    compliance certificate.
    """

    __tablename__ = "digital_product_passports"

    passport_id = Column(String, primary_key=True, index=True)
    omni_id = Column(
        String,
        ForeignKey("assets.omni_id"),
        unique=True,
        index=True,
        nullable=False,
    )
    tenant_id = Column(String, index=True, nullable=False)

    passport_level = Column(String, nullable=False, default="item")
    product_name = Column(String, nullable=True)
    brand_name = Column(String, nullable=True)

    # GS1 instance-identification inputs. Omni Veil validates syntax/check digit
    # but does not claim ownership/licensing rights over the supplied GS1 key.
    gtin14 = Column(String, nullable=True)
    serial_number = Column(String, nullable=True)
    data_carrier_type = Column(String, nullable=True)
    canonical_gs1_uri = Column(Text, nullable=True)
    resolver_uri = Column(Text, nullable=True)

    # Pin the implementation profile so future standard upgrades are explicit.
    gs1_uri_syntax_version = Column(String, nullable=False, default="1.7.0")
    gs1_resolver_standard_version = Column(String, nullable=False, default="1.2.1")
    regulatory_framework = Column(
        String,
        nullable=False,
        default="Regulation (EU) 2024/1781",
    )
    regulatory_status = Column(String, nullable=False, default="readiness_only")

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
