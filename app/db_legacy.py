from sqlalchemy import create_engine, Column, String, Float, Boolean, DateTime, Text, Integer
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
import os

DATABASE_URL = "sqlite:///./omniveil.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class Asset(Base):
    __tablename__ = "assets"
    omni_id = Column(String, primary_key=True, index=True)
    asset_id = Column(String)
    sha256 = Column(String)
    blake3 = Column(String)
    phash = Column(String, nullable=True)
    trust_score = Column(Float)
    content_label = Column(String)
    label_reasons = Column(Text)
    ai_detection_score = Column(Float, nullable=True)
    watermark_applied = Column(Boolean)
    watermark_visible = Column(Boolean, default=False)
    watermark_invisible = Column(Boolean, default=False)
    mime_type = Column(String)
    asset_type = Column(String)
    file_size_bytes = Column(Integer, nullable=True)
    creator_name = Column(String, nullable=True)
    total_verifications = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)
    registry_url = Column(String, nullable=True)

def init_db():
    Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def save_asset(db, data: dict):
    import json
    asset = Asset(
        omni_id=data["omni_id"],
        asset_id=data.get("asset_id",""),
        sha256=data.get("sha256",""),
        blake3=data.get("blake3",""),
        phash=data.get("phash"),
        trust_score=data.get("trust_score",0.5),
        content_label=data.get("content_label","unverified"),
        label_reasons=json.dumps(data.get("label_reasons",[])),
        ai_detection_score=data.get("ai_detection_score"),
        watermark_applied=data.get("watermark_applied",False),
        watermark_visible=data.get("watermark_visible",False),
        watermark_invisible=data.get("watermark_invisible",False),
        mime_type=data.get("mime_type","application/octet-stream"),
        asset_type=data.get("asset_type","file"),
        file_size_bytes=data.get("file_size_bytes"),
        creator_name=data.get("creator_name"),
        total_verifications=0,
        registry_url=data.get("registry_url",""),
    )
    db.merge(asset)
    db.commit()
    return asset

def get_asset(db, omni_id: str):
    return db.query(Asset).filter(Asset.omni_id==omni_id).first()

def get_all_assets(db, limit=50):
    return db.query(Asset).order_by(Asset.created_at.desc()).limit(limit).all()
