from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

from src.config import settings

# Respect the DATABASE_URL provided in settings. For SQLite keep same-thread disabled.
DATABASE_URL = settings.DATABASE_URL

connect_args = {}
if DATABASE_URL.startswith("sqlite"):
    connect_args = {"check_same_thread": False}

engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def _ensure_sqlite_schema():
    """Ensure SQLite schema includes newer columns when running against an existing DB file."""
    if not DATABASE_URL.startswith("sqlite"):
        return

    # Use SQLite PRAGMA to inspect columns
    from sqlalchemy import text

    with engine.connect() as conn:
        res = conn.execute(text("PRAGMA table_info('audit_log')"))
        rows = res.fetchall()
        # If the table does not exist yet, skip best-effort ALTERs — Alembic will create schema.
        if not rows:
            return

        cols = [row[1] for row in rows]
        if "redacted_fingerprint" not in cols:
            # Add the missing column (best-effort migration)
            conn.execute(text("ALTER TABLE audit_log ADD COLUMN redacted_fingerprint VARCHAR(128)"))
            conn.commit()


# Create tables if missing and ensure schema compatibility for SQLite
Base.metadata.create_all(bind=engine)
_ensure_sqlite_schema()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
