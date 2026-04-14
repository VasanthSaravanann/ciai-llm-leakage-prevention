"""
CIAI FastAPI Control Plane
==========================
API endpoints for:
  - /detect  – analyze text for sensitive data
  - /health  – health check
  - /log     – store audit events + send email alerts (Phase 2)

Security (Phase 2 remediation):
  - API key authentication on /detect and /log (VULN-004)
  - Rate limiting via slowapi (VULN-005)
  - XSS input sanitization (VULN-006)
  - Security headers (VULN-012)
  - Database file permissions (VULN-011)
  - Sanitized error responses (VULN-015)
"""

import os
import html
import logging
from contextlib import asynccontextmanager

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, Field
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from src.detection.detect import detect_sensitive
from src.logging.db import init_db, create_audit_log, get_audit_logs
from src.logging.alerts import send_alert_email, should_send_alert

# Load environment variables from .env file (if present)
load_dotenv()

logger = logging.getLogger("ciai.api")


# ---------------------------------------------------------------------------
# Security: Authentication (VULN-004)
# ---------------------------------------------------------------------------

security = HTTPBearer(auto_error=False)

API_KEY = os.getenv("API_KEY", "")


def verify_api_key(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Verify Bearer token matches API_KEY env var."""
    if not API_KEY:
        # No API_KEY set — skip auth (dev mode warning)
        return

    if credentials is None or credentials.credentials != API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key",
            headers={"WWW-Authenticate": "Bearer"},
        )


# ---------------------------------------------------------------------------
# Security: Rate Limiting (VULN-005)
# ---------------------------------------------------------------------------

limiter = Limiter(key_func=get_remote_address)


def rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded):
    """Return 429 for rate-limited requests."""
    return JSONResponse(
        status_code=429,
        content={"error": "Rate limit exceeded. Try again later."},
    )


# ---------------------------------------------------------------------------
# Security: Input Sanitization (VULN-006)
# ---------------------------------------------------------------------------

def sanitize_for_storage(value: str) -> str:
    """Escape HTML entities to prevent stored XSS."""
    return html.escape(value, quote=True)


# ---------------------------------------------------------------------------
# Application lifecycle
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize database and set secure file permissions on startup."""
    # VULN-011: Restrict file permissions
    os.umask(0o077)

    await init_db()
    logger.info("CIAI database initialized")

    # Ensure data directory is restricted
    data_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data")
    if os.path.exists(data_dir):
        os.chmod(data_dir, 0o700)

    yield


app = FastAPI(
    title="CIAI – LLM Data Leakage Prevention",
    description="Detect and prevent sensitive data leakage to LLMs",
    version="0.3.0",
    lifespan=lifespan
)

# Register rate limiter
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, rate_limit_exceeded_handler)


# ---------------------------------------------------------------------------
# Security: Sanitized Error Responses (VULN-015)
# ---------------------------------------------------------------------------

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Return generic validation errors without leaking framework internals."""
    return JSONResponse(
        status_code=422,
        content={
            "error": "Invalid request",
            "message": "One or more fields failed validation"
        }
    )


# ---------------------------------------------------------------------------
# Security: Security Headers Middleware (VULN-012)
# ---------------------------------------------------------------------------

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Cache-Control"] = "no-store"
        # Remove server header (MutableHeaders uses del)
        if "server" in response.headers:
            del response.headers["server"]
        return response


app.add_middleware(SecurityHeadersMiddleware)


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
    user_id: str = Field(..., min_length=1, max_length=255, description="User identifier")
    redacted_prompt: str = Field(..., min_length=1, max_length=100_000, description="Redacted prompt text")
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
@limiter.limit("60/minute")
async def health(request: Request):
    """Health check endpoint — no auth required."""
    return {"status": "ok", "service": "ciai-detection"}


@app.post("/detect", response_model=DetectResponse, dependencies=[Depends(verify_api_key)])
@limiter.limit("30/minute")
async def detect(request: Request, req: DetectRequest):
    """
    Analyze text for sensitive data (PII, secrets, India-specific IDs).

    Returns detection types, block/redact decision, and redacted text.
    Requires API key authentication (set API_KEY env var).
    """
    try:
        result = detect_sensitive(req.text)
        return DetectResponse(**result)
    except Exception as e:
        logger.error(f"Detection error: {e}")
        raise HTTPException(status_code=500, detail="Detection failed")


@app.post("/log", response_model=LogResponse, dependencies=[Depends(verify_api_key)])
@limiter.limit("60/minute")
async def log_event(request: Request, req: LogRequest, background_tasks: BackgroundTasks):
    """
    Store an audit log entry in SQLite and send email alert if high severity.

    - Persists detection event to SQLite
    - Triggers async email alert for high-severity detections
    - Returns log entry ID
    - Sanitizes input to prevent stored XSS
    Requires API key authentication (set API_KEY env var).
    """
    try:
        # VULN-006: Sanitize input to prevent stored XSS
        sanitized_user_id = sanitize_for_storage(req.user_id)
        sanitized_prompt = sanitize_for_storage(req.redacted_prompt)
        sanitized_llm_response = sanitize_for_storage(req.llm_response_redacted) if req.llm_response_redacted else None

        severity = _determine_severity(req.detection_types)

        # Persist to SQLite
        log_id = await create_audit_log(
            user_id=sanitized_user_id,
            redacted_prompt=sanitized_prompt,
            detection_types=req.detection_types,
            action_taken=req.action,
            llm_response_redacted=sanitized_llm_response,
            severity=severity,
        )

        # Build entry dict for email
        entry = {
            "id": log_id,
            "user_id": sanitized_user_id,
            "redacted_prompt": sanitized_prompt,
            "detection_types": ", ".join(req.detection_types),
            "action_taken": req.action,
            "severity": severity,
            "timestamp": "just now",
        }

        # Queue email alert in background (non-blocking)
        if should_send_alert(severity):
            background_tasks.add_task(send_alert_email, entry)

        return LogResponse(status="logged", id=log_id)

    except Exception as e:
        logger.error(f"Failed to log event: {e}")
        raise HTTPException(status_code=500, detail="Logging failed")


def _determine_severity(detection_types: list[str]) -> str:
    """Determine severity based on detection types."""
    high_types = {
        "AADHAAR", "PAN", "CREDIT_CARD", "OPENAI_KEY", "ANTHROPIC_KEY",
        "AWS_KEY", "AWS_SECRET", "BEARER_TOKEN", "GENERIC_API_KEY", "GENERIC_SECRET",
        # India-specific
        "VOTER_ID", "DRIVING_LICENSE", "GST_NUMBER", "PASSPORT",
        # Base64 variants
        "BASE64_AADHAAR", "BASE64_PAN", "BASE64_CREDIT_CARD",
        "BASE64_VOTER_ID", "BASE64_DRIVING_LICENSE", "BASE64_GST_NUMBER",
        "BASE64_PASSPORT", "BASE64_US_SSN",
    }
    if any(dt in high_types for dt in detection_types):
        return "high"
    elif len(detection_types) >= 2:
        return "medium"
    elif len(detection_types) == 1:
        return "low"
    return "none"
