import os
import sys

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker

ENVIRONMENT = os.getenv("ENVIRONMENT", "development").lower()
DATABASE_URL = os.getenv("DATABASE_URL", "")

if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

if ENVIRONMENT == "production":
    if not DATABASE_URL or DATABASE_URL.startswith("sqlite"):
        print(
            "FATAL: ENVIRONMENT=production requires a real Postgres DATABASE_URL. "
            "SQLite is not allowed in production.",
            file=sys.stderr,
        )
        sys.exit(1)

if not DATABASE_URL:
    DATABASE_URL = "sqlite:///./omniveil.db"
    print(
        "WARNING: DATABASE_URL not set. Using local SQLite for development only.",
        file=sys.stderr,
    )

IS_SQLITE = DATABASE_URL.startswith("sqlite")

engine_kwargs = {"pool_pre_ping": True}

if IS_SQLITE:
    engine_kwargs = {
        "connect_args": {"check_same_thread": False},
    }

engine = create_engine(DATABASE_URL, **engine_kwargs)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    from app.db.base import Base
    import app.db.models  # noqa: F401

    Base.metadata.create_all(bind=engine)
    _run_migrations()


def _column_exists(conn, table: str, column: str) -> bool:
    if IS_SQLITE:
        rows = conn.execute(text(f"PRAGMA table_info({table})")).fetchall()
        return column in {row[1] for row in rows}

    result = conn.execute(
        text(
            """
            SELECT column_name
            FROM information_schema.columns
            WHERE table_name = :table
            AND column_name = :column
            """
        ),
        {"table": table, "column": column},
    ).fetchone()
    return result is not None


def _run_migrations():
    """
    Additive migrations only.
    Safe to run repeatedly.
    Supports SQLite for local dev and Postgres for Render production.
    """
    additions = [
        # assets — human authorship evidence
        ("assets", "human_creative_direction", "BOOLEAN"),
        ("assets", "human_editing_present", "BOOLEAN"),
        ("assets", "human_arrangement_present", "BOOLEAN"),
        ("assets", "human_lyrics_present", "BOOLEAN"),
        ("assets", "human_performance_present", "BOOLEAN"),
        ("assets", "human_transformation_present", "BOOLEAN"),

        # assets — copyright readiness
        ("assets", "copyright_readiness_score", "REAL"),
        ("assets", "copyright_readiness_label", "VARCHAR"),
        ("assets", "ai_disclosure_complete", "BOOLEAN"),
        ("assets", "ai_tools_used_json", "TEXT"),
        ("assets", "ai_modification_by_human", "BOOLEAN"),
        ("assets", "human_authorship_summary", "TEXT"),

        # assets — certificate class, tenant support
        ("assets", "certificate_class", "VARCHAR"),
        ("assets", "certificate_class_label", "VARCHAR"),
        ("assets", "tenant_id", "VARCHAR"),

        # certificates — certificate class
        ("certificates", "certificate_class", "VARCHAR"),

        # contributors — live-split three-column model
        ("contributors", "creative_contribution_pct", "REAL"),
        ("contributors", "ownership_split_pct", "REAL"),
        ("contributors", "ai_assisted_pct", "REAL"),

        # live split sessions — tenant support
        ("live_split_sessions", "tenant_id", "VARCHAR"),
    ]

    with engine.connect() as conn:
        inspector = inspect(conn)
        existing_tables = set(inspector.get_table_names())

        for table, column, col_type in additions:
            if table not in existing_tables:
                continue

            if not _column_exists(conn, table, column):
                conn.execute(
                    text(f"ALTER TABLE {table} ADD COLUMN {column} {col_type}")
                )
                print(f"Migration applied: {table}.{column}")

        conn.commit()
