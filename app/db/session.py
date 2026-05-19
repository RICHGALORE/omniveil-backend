from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
import os

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./omniveil.db")

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    from app.db.base import Base
    import app.db.models  # noqa: F401 — registers all ORM models with Base
    Base.metadata.create_all(bind=engine)
    _run_migrations()


def _run_migrations():
    """
    Apply additive schema migrations for SQLite.
    create_all() only creates missing tables; ALTER TABLE is required for new
    columns on existing tables.  Each entry is (table, column, DDL_type).
    """
    additions = [
        # assets — human authorship evidence
        ("assets", "human_creative_direction",  "BOOLEAN"),
        ("assets", "human_editing_present",     "BOOLEAN"),
        ("assets", "human_arrangement_present", "BOOLEAN"),
        ("assets", "human_lyrics_present",      "BOOLEAN"),
        ("assets", "human_performance_present", "BOOLEAN"),
        ("assets", "human_transformation_present", "BOOLEAN"),
        # assets — copyright readiness
        ("assets", "copyright_readiness_score", "REAL"),
        ("assets", "copyright_readiness_label", "VARCHAR"),
        ("assets", "ai_disclosure_complete",    "BOOLEAN"),
        ("assets", "ai_tools_used_json",        "TEXT"),
        ("assets", "ai_modification_by_human",  "BOOLEAN"),
        ("assets", "human_authorship_summary",  "TEXT"),
        # certificates — certificate class
        ("certificates", "certificate_class",   "VARCHAR"),
        # contributors — live-split three-column model
        ("contributors", "creative_contribution_pct", "REAL"),
        ("contributors", "ownership_split_pct",       "REAL"),
        ("contributors", "ai_assisted_pct",           "REAL"),
    ]

    with engine.connect() as conn:
        for table, column, col_type in additions:
            existing = {
                row[1]
                for row in conn.execute(text(f"PRAGMA table_info({table})")).fetchall()
            }
            if column not in existing:
                conn.execute(text(
                    f"ALTER TABLE {table} ADD COLUMN {column} {col_type}"
                ))
        conn.commit()
