"""
CIAI SQLite Persistence Layer
==============================
Async SQLAlchemy engine for audit log storage.
Uses aiosqlite for non-blocking SQLite operations.
"""

import os
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import Column, Integer, String, DateTime, Text, text


# ---------------------------------------------------------------------------
# Database configuration
# ---------------------------------------------------------------------------

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "sqlite+aiosqlite:///./data/ciai_audit.db"
)

engine = create_async_engine(
    DATABASE_URL,
    echo=False,  # set True for SQL debugging
    future=True
)

AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False
)


# ---------------------------------------------------------------------------
# SQLAlchemy Base + Model
# ---------------------------------------------------------------------------

class Base(DeclarativeBase):
    pass


async def _ensure_sqlite_schema():
    """Ensure SQLite schema includes newer columns when running against an existing DB file."""
    if not DATABASE_URL.startswith("sqlite"):
        return

    async with engine.begin() as conn:
        res = await conn.execute(text("PRAGMA table_info('audit_logs')"))
        rows = res.fetchall()
        if not rows:
            return

        cols = [row[1] for row in rows]
        if "tenant_id" not in cols:
            await conn.execute(text("ALTER TABLE audit_logs ADD COLUMN tenant_id VARCHAR(255)"))


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    user_id = Column(String(255), nullable=False, index=True)
    tenant_id = Column(String(255), nullable=True, index=True)
    redacted_prompt = Column(Text, nullable=False)
    detection_types = Column(String(500), nullable=False)  # JSON array as string
    action_taken = Column(String(20), nullable=False)  # "block" or "redact"
    llm_response_redacted = Column(Text, nullable=True)
    severity = Column(String(20), nullable=False, index=True)  # "high", "medium", "low"

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "user_id": self.user_id,
            "tenant_id": self.tenant_id,
            "redacted_prompt": self.redacted_prompt,
            "detection_types": self.detection_types,
            "action_taken": self.action_taken,
            "llm_response_redacted": self.llm_response_redacted,
            "severity": self.severity,
        }


# ---------------------------------------------------------------------------
# Database operations
# ---------------------------------------------------------------------------

async def init_db():
    """Create tables if they don't exist. Call on app startup."""
    async with engine.begin() as conn:
        if DATABASE_URL.startswith("sqlite"):
            # SQLite-only tuning; Postgres rejects PRAGMA statements.
            await conn.execute(text("PRAGMA journal_mode=WAL"))
            await conn.execute(text("PRAGMA busy_timeout=5000"))
        await conn.run_sync(Base.metadata.create_all)


async def create_audit_log(
    user_id: str,
    redacted_prompt: str,
    detection_types: list[str],
    action_taken: str,
    llm_response_redacted: Optional[str] = None,
    severity: str = "low",
    tenant_id: Optional[str] = None,
) -> int:
    """
    Insert a new audit log entry.

    Returns the new entry's ID.
    """
    import json

    await _ensure_sqlite_schema()

    async with AsyncSessionLocal() as session:
        entry = AuditLog(
            user_id=user_id,
            tenant_id=tenant_id,
            redacted_prompt=redacted_prompt,
            detection_types=json.dumps(detection_types),
            action_taken=action_taken,
            llm_response_redacted=llm_response_redacted,
            severity=severity,
        )
        session.add(entry)
        await session.commit()
        await session.refresh(entry)
        return entry.id


async def get_audit_logs(
    limit: int = 100,
    offset: int = 0,
    severity_filter: Optional[str] = None,
    user_id_filter: Optional[str] = None,
    tenant_id_filter: Optional[str] = None,
) -> list[dict]:
    """
    Query audit logs (newest first).

    Supports optional severity and user_id filtering.
    """
    import json
    from sqlalchemy import select, desc

    async with AsyncSessionLocal() as session:
        query = select(AuditLog).order_by(desc(AuditLog.timestamp))

        if severity_filter:
            query = query.where(AuditLog.severity == severity_filter)
        if user_id_filter:
            query = query.where(AuditLog.user_id == user_id_filter)
        if tenant_id_filter:
            query = query.where(AuditLog.tenant_id == tenant_id_filter)

        query = query.limit(limit).offset(offset)
        result = await session.execute(query)
        logs = result.scalars().all()

        return [log.to_dict() for log in logs]
