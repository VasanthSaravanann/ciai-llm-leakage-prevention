from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, JSON, Text

from .database import Base


class AuditLog(Base):
    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    user_id = Column(String, index=True)
    tenant_id = Column(String, index=True, nullable=True)
    # Store only redacted prompt text (no raw prompt). Keep fingerprint for lookup.
    redacted_prompt = Column(Text)
    redacted_fingerprint = Column(String(128), index=True)
    # New columns for encrypted storage (ciphertext stored base64-encoded)
    redacted_prompt_ciphertext = Column(Text, nullable=True)
    redacted_prompt_key_id = Column(String(256), nullable=True)
    detection_types = Column(JSON)  # Store list of strings
    trace_metadata = Column(JSON, nullable=True)
    action = Column(String)  # "block" or "redact" or "pass"
    severity = Column(String)
    llm_response_redacted = Column(Text, nullable=True)
