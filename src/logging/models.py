from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, JSON

from .database import Base


class AuditLog(Base):
    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    user_id = Column(String, index=True)
    redacted_prompt = Column(String)
    detection_types = Column(JSON)  # Store list of strings
    action = Column(String)  # "block" or "redact" or "pass"
    severity = Column(String)
    llm_response_redacted = Column(String, nullable=True)
