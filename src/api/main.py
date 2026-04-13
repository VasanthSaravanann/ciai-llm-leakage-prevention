"""
CIAI FastAPI Control Plane
==========================
API endpoints for:
  - /detect  – analyze text for sensitive data
  - /health  – health check
  - /log     – store audit events (Phase 2)
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from src.detection.detect import detect_sensitive

app = FastAPI(
    title="CIAI – LLM Data Leakage Prevention",
    description="Detect and prevent sensitive data leakage to LLMs",
    version="0.1.0"
)


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class DetectRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=100_000, description="Text to analyze")


class DetectResponse(BaseModel):
    detections: list[str]
    block: bool
    redact: bool
    redacted_text: str
    severity: str


class LogRequest(BaseModel):
    user_id: str = Field(..., description="User identifier")
    redacted_prompt: str = Field(..., description="Redacted prompt text")
    detection_types: list[str] = Field(default_factory=list, description="Detected types")
    action: str = Field(..., description="Action taken: block or redact")
    llm_response_redacted: str | None = Field(None, description="Redacted LLM response")


class LogResponse(BaseModel):
    status: str
    id: int | None = None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "ok", "service": "ciai-detection"}


@app.post("/detect", response_model=DetectResponse)
async def detect(req: DetectRequest):
    """
    Analyze text for sensitive data (PII, secrets, India-specific IDs).

    Returns detection types, block/redact decision, and redacted text.
    """
    try:
        result = detect_sensitive(req.text)
        return DetectResponse(**result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Detection error: {str(e)}")


@app.post("/log", response_model=LogResponse)
async def log_event(req: LogRequest):
    """
    Store an audit log entry.

    NOTE: This is a placeholder for Phase 1.
    Full SQLite + email alerting implementation in Phase 2.
    """
    # TODO: Phase 2 – persist to SQLite and send email alerts
    return LogResponse(status="logged (placeholder – Phase 2)")
