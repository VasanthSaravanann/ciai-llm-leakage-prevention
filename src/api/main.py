"""
CIAI FastAPI Control Plane
==========================
API endpoints for:
  - /detect  – analyze text for sensitive data
  - /health  – health check
  - /log     – store audit events + send email alerts (Phase 2)
  - /dashboard – real-time audit log viewer (Phase 4)

Security:
  - API key authentication (X-API-KEY header)
  - XSS input sanitization
  - Rate limiting via slowapi
  - Security headers (HSTS, CSP, X-Frame, etc.)
"""

import html
import logging
import os

from fastapi import FastAPI, HTTPException, Depends, Security, BackgroundTasks, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.security.api_key import APIKeyHeader
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from sqlalchemy import desc
from starlette.status import HTTP_403_FORBIDDEN
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from src.detection.detect import detect_sensitive
from src.config import settings
from src.logging.database import engine, get_db, SessionLocal
from src.logging.models import Base, AuditLog
from src.logging.alerts import send_alert_email, should_send_alert

# Initialize database
Base.metadata.create_all(bind=engine)

# Security: File permissions
os.umask(0o077)

# Setup templates
templates = Jinja2Templates(directory="src/api/templates")

app = FastAPI(
    title=settings.API_TITLE,
    description="Detect and prevent sensitive data leakage to LLMs",
    version=settings.API_VERSION
)

# API Key Security
api_key_header = APIKeyHeader(name=settings.API_KEY_NAME, auto_error=False)


async def get_api_key(api_key: str = Security(api_key_header)):
    if api_key == settings.API_KEY:
        return api_key
    raise HTTPException(
        status_code=HTTP_403_FORBIDDEN, detail="Invalid or missing API key"
    )


# Rate Limiting
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter


def rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(status_code=429, content={"error": "Rate limit exceeded"})


app.add_exception_handler(RateLimitExceeded, rate_limit_exceeded_handler)


# Security Headers Middleware
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Cache-Control"] = "no-store"
        return response


app.add_middleware(SecurityHeadersMiddleware)


# XSS sanitization helper
def sanitize(value: str) -> str:
    return html.escape(value, quote=True) if value else value


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
    action: str = Field(..., description="Action taken: block, redact, or pass")
    severity: str = Field(default="low", description="Detection severity")
    llm_response_redacted: str | None = Field(None, description="Redacted LLM response")


class LogResponse(BaseModel):
    status: str
    id: int | None = None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/health")
@limiter.limit("60/minute")
async def health(request: Request):
    """Health check endpoint."""
    return {"status": "ok", "service": "ciai-detection"}


@app.get("/dashboard", response_class=HTMLResponse)
@limiter.limit("30/minute")
async def dashboard(request: Request, db: Session = Depends(get_db)):
    """Render the audit log dashboard."""
    logs = db.query(AuditLog).order_by(desc(AuditLog.timestamp)).limit(100).all()
    return templates.TemplateResponse("dashboard.html", {"request": request, "logs": logs})


def _log_detection_background(result: dict):
    """Background task to log detection events without slowing down the API."""
    db = SessionLocal()
    try:
        db_log = AuditLog(
            user_id="direct-api",
            redacted_prompt=sanitize(result["redacted_text"]),
            detection_types=result["detections"],
            action="block" if result["block"] else "redact",
            severity=result["severity"]
        )
        db.add(db_log)
        db.commit()
    except Exception as e:
        db.rollback()
    finally:
        db.close()


@app.post("/detect", response_model=DetectResponse, dependencies=[Depends(get_api_key)])
@limiter.limit("30/minute")
async def detect(request: Request, req: DetectRequest, background_tasks: BackgroundTasks):
    """Analyze text for sensitive data (PII, secrets, India-specific IDs)."""
    try:
        result = detect_sensitive(req.text)

        # Phase 4: Auto-log detection events in background
        if result["detections"]:
            background_tasks.add_task(_log_detection_background, result)

        return DetectResponse(**result)
    except Exception as e:
        raise HTTPException(status_code=500, detail="Detection failed")


@app.post("/log", response_model=LogResponse, dependencies=[Depends(get_api_key)])
@limiter.limit("60/minute")
async def log_event(
    request: Request,
    req: LogRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """Store an audit log entry in SQLite and trigger alerts if needed."""
    try:
        # XSS sanitization
        sanitized_user_id = sanitize(req.user_id)
        sanitized_prompt = sanitize(req.redacted_prompt)
        sanitized_response = sanitize(req.llm_response_redacted) if req.llm_response_redacted else None

        # 1. Synchronous insert (returns ID immediately)
        db_log = AuditLog(
            user_id=sanitized_user_id,
            redacted_prompt=sanitized_prompt,
            detection_types=req.detection_types,
            action=req.action,
            severity=req.severity,
            llm_response_redacted=sanitized_response
        )
        db.add(db_log)
        db.commit()
        db.refresh(db_log)

        # 2. Trigger email alert for HIGH severity in background
        if should_send_alert(req.severity):
            background_tasks.add_task(
                send_alert_email,
                entry={
                    "user_id": sanitized_user_id,
                    "redacted_prompt": sanitized_prompt,
                    "detection_types": ", ".join(req.detection_types),
                    "action_taken": req.action,
                    "severity": req.severity,
                }
            )

        return LogResponse(status="logged", id=db_log.id)
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail="Logging failed")
