import os
import sys

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker

ENVIRONMENT = os.getenv("ENVIRONMENT", "development").lower()
DATABASE_URL = os.getenv("DATABASE_URL", "")

if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

# Use modern psycopg v3 driver for Postgres.
# This avoids psycopg2 SSL/runtime issues in production deploys.
if DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)

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

        # asset_metadata — Metadata Trust Score (Commit 3)
        ("asset_metadata", "metadata_trust_score", "INTEGER"),
        ("asset_metadata", "metadata_score_breakdown_json", "TEXT"),
        ("asset_metadata", "metadata_score_engine_version", "VARCHAR"),
        ("asset_metadata", "metadata_scored_at", "TIMESTAMP"),

        # asset_metadata — Metadata Anomaly Intelligence (Commit 4)
        ("asset_metadata", "anomaly_score", "INTEGER"),
        ("asset_metadata", "anomaly_flags_json", "TEXT"),
        ("asset_metadata", "anomaly_engine_version", "TEXT"),
        ("asset_metadata", "anomaly_scored_at", "TIMESTAMP"),
    ]

    # ── New-table creations (additive, idempotent) ────────────────────────────
    # Base.metadata.create_all() already creates these from the ORM models; the
    # statements below are an explicit, idempotent safety net so the schema is
    # guaranteed even if create_all is bypassed. CREATE TABLE/INDEX IF NOT EXISTS
    # is supported by both SQLite (dev) and PostgreSQL (production).
    table_creations = [
        (
            "asset_metadata",
            """
            CREATE TABLE IF NOT EXISTS asset_metadata (
                id VARCHAR PRIMARY KEY,
                asset_id VARCHAR NOT NULL UNIQUE,
                omni_id VARCHAR,
                tenant_id VARCHAR,
                engine_name VARCHAR,
                engine_version VARCHAR,
                extractor VARCHAR,
                exiftool_available BOOLEAN,
                supported BOOLEAN,
                raw_metadata_json TEXT,
                normalized_metadata_json TEXT,
                derived_metadata_json TEXT,
                warnings_json TEXT,
                metadata_sha256 VARCHAR,
                extraction_duration_ms FLOAT,
                metadata_trust_score INTEGER,
                metadata_score_breakdown_json TEXT,
                metadata_score_engine_version VARCHAR,
                metadata_scored_at TIMESTAMP,
                anomaly_score INTEGER,
                anomaly_flags_json TEXT,
                anomaly_engine_version TEXT,
                anomaly_scored_at TIMESTAMP,
                analyzed_at TIMESTAMP,
                created_at TIMESTAMP,
                updated_at TIMESTAMP
            )
            """,
            [
                "CREATE INDEX IF NOT EXISTS ix_asset_metadata_asset_id ON asset_metadata (asset_id)",
                "CREATE INDEX IF NOT EXISTS ix_asset_metadata_omni_id ON asset_metadata (omni_id)",
                "CREATE INDEX IF NOT EXISTS ix_asset_metadata_tenant_id ON asset_metadata (tenant_id)",
                "CREATE INDEX IF NOT EXISTS ix_asset_metadata_metadata_sha256 ON asset_metadata (metadata_sha256)",
            ],
        ),
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

        for table, create_sql, index_sqls in table_creations:
            created = table not in existing_tables
            conn.execute(text(create_sql))
            for index_sql in index_sqls:
                conn.execute(text(index_sql))
            if created:
                print(f"Migration applied: created table {table}")

        # All records created before tenant support belonged to the founder's
        # demo tenant. Preserve those records without exposing them to future
        # tenants. This only runs when that tenant already exists.
        demo_tenant_id = os.getenv("DEMO_TENANT_ID", "demo-tenant")
        if {"assets", "clients"}.issubset(existing_tables):
            demo_exists = conn.execute(
                text("SELECT 1 FROM clients WHERE tenant_id = :tenant_id LIMIT 1"),
                {"tenant_id": demo_tenant_id},
            ).fetchone()
            if demo_exists:
                conn.execute(
                    text(
                        "UPDATE assets SET tenant_id = :tenant_id "
                        "WHERE tenant_id IS NULL OR tenant_id = ''"
                    ),
                    {"tenant_id": demo_tenant_id},
                )

        conn.commit()
