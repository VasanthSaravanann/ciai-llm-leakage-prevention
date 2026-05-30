from collections import deque
import threading

from src.config import get_api_keys
from src.config import settings
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
import os

from fastapi import FastAPI, HTTPException, Depends, Security, BackgroundTasks, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.security.api_key import APIKeyHeader
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from sqlalchemy import desc
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
from starlette.status import HTTP_403_FORBIDDEN

from src.detection.detect import detect_sensitive
from src.auth import authenticate_request, ensure_permission, require_tenant
from src.logging.database import engine, get_db, SessionLocal
from src.logging.models import Base, AuditLog
from src.logging.alerts import send_alert_email, should_send_alert
from src.logging.encryption import encrypt as _encrypt
import base64
from src.rate_limiter import RateLimiter
from src.moderation.moderator import moderate_response

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

cors_origins = [origin.strip() for origin in getattr(settings, "CORS_ORIGINS", "").split(",") if origin.strip()]
if cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

# Rate limiter instance
rate_limiter = RateLimiter(getattr(settings, 'REDIS_URL', None))

# API Key Security
api_key_header = APIKeyHeader(name=settings.API_KEY_NAME, auto_error=False)


async def get_api_key(request: Request, api_key: str = Security(api_key_header)):
    # Accept any key present in the configured API_KEYS list (rotatable)
    valid_keys = get_api_keys()
    if api_key in valid_keys:
        return api_key

    # Also allow JWT/OIDC bearer tokens from Authorization header.
    try:
        ctx = authenticate_request(request)
        if ctx.get("auth_type") in {"jwt", "oidc_jwt"}:
            return "bearer"
    except HTTPException:
        pass

    raise HTTPException(
        status_code=HTTP_403_FORBIDDEN, detail="Invalid or missing API key"
    )

# Prometheus metrics (simple)
try:
    from prometheus_client import Counter, generate_latest, CONTENT_TYPE_LATEST
    REQUEST_COUNTER = Counter('ciai_requests_total', 'Total requests to CIAI API')
    DETECTION_TOTAL_COUNTER = Counter('ciai_detection_total', 'Total detection attempts')
    DETECTION_ERROR_COUNTER = Counter('ciai_detection_errors_total', 'Total detection failures')
    SLO_BREACH_COUNTER = Counter('ciai_slo_breaches_total', 'SLO breach events observed by application')
    try:
        from prometheus_client import Histogram
        DETECTION_LATENCY = Histogram('ciai_detection_latency_seconds', 'Detection latency in seconds')
        REQUEST_LATENCY = Histogram('ciai_request_latency_seconds', 'API request latency in seconds')
    except Exception:
        DETECTION_LATENCY = None
        REQUEST_LATENCY = None
except Exception:
    REQUEST_COUNTER = None
    DETECTION_TOTAL_COUNTER = None
    DETECTION_ERROR_COUNTER = None
    SLO_BREACH_COUNTER = None
    DETECTION_LATENCY = None
    REQUEST_LATENCY = None


_SLO_LOCK = threading.Lock()
_DETECTION_LATENCY_WINDOW = deque(maxlen=3000)
_DETECTION_TOTAL = 0
_DETECTION_ERRORS = 0


def _record_detection_slo(latency_seconds: float, is_error: bool) -> dict | None:
    """Track in-memory SLO window and return breach metadata when threshold is exceeded."""
    global _DETECTION_TOTAL, _DETECTION_ERRORS
    with _SLO_LOCK:
        _DETECTION_TOTAL += 1
        if is_error:
            _DETECTION_ERRORS += 1
        _DETECTION_LATENCY_WINDOW.append(latency_seconds)

        # Not enough samples to evaluate meaningful p95.
        if len(_DETECTION_LATENCY_WINDOW) < 20:
            return None

        vals = sorted(_DETECTION_LATENCY_WINDOW)
        idx = max(0, int(0.95 * (len(vals) - 1)))
        p95_ms = vals[idx] * 1000.0
        err_rate = _DETECTION_ERRORS / max(1, _DETECTION_TOTAL)

        slo_p95_target = float(getattr(settings, "SLO_P95_DETECTION_MS", 300))
        slo_error_target = float(getattr(settings, "SLO_MAX_DETECTION_ERROR_RATE", 0.01))

        if p95_ms > slo_p95_target or err_rate > slo_error_target:
            if SLO_BREACH_COUNTER:
                SLO_BREACH_COUNTER.inc()
            return {
                "p95_ms": round(p95_ms, 2),
                "error_rate": round(err_rate, 4),
                "p95_target_ms": slo_p95_target,
                "error_target": slo_error_target,
            }
        return None



# Rate Limiting: use Redis backend when available for shared quotas
storage_uri = getattr(settings, 'REDIS_URL', None)
if storage_uri:
    limiter = Limiter(key_func=get_remote_address, storage_uri=storage_uri)
else:
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
    ensure_permission(request, "view_metrics")
    if REQUEST_COUNTER:
        REQUEST_COUNTER.inc()
    return {"status": "ok", "service": "ciai-detection"}


@app.get('/metrics')
async def metrics(request: Request):
    ensure_permission(request, "view_metrics")
    if REQUEST_COUNTER is None:
        return Response(content='metrics_unavailable', media_type='text/plain')
    data = generate_latest()
    return Response(content=data, media_type=CONTENT_TYPE_LATEST)


@app.get('/slo')
async def slo_status(request: Request):
    """Application-level SLO snapshot (short moving window)."""
    ensure_permission(request, "view_metrics")
    with _SLO_LOCK:
        if not _DETECTION_LATENCY_WINDOW:
            return {
                "window_size": 0,
                "detection_error_rate": 0,
                "p95_detection_ms": 0,
                "targets": {
                    "p95_detection_ms": settings.SLO_P95_DETECTION_MS,
                    "max_detection_error_rate": settings.SLO_MAX_DETECTION_ERROR_RATE,
                },
            }
        vals = sorted(_DETECTION_LATENCY_WINDOW)
        idx = max(0, int(0.95 * (len(vals) - 1)))
        p95_ms = vals[idx] * 1000.0
        error_rate = _DETECTION_ERRORS / max(1, _DETECTION_TOTAL)
        return {
            "window_size": len(_DETECTION_LATENCY_WINDOW),
            "detection_error_rate": round(error_rate, 4),
            "p95_detection_ms": round(p95_ms, 2),
            "targets": {
                "p95_detection_ms": settings.SLO_P95_DETECTION_MS,
                "max_detection_error_rate": settings.SLO_MAX_DETECTION_ERROR_RATE,
            },
        }


@app.get("/dashboard", response_class=HTMLResponse)
@limiter.limit("30/minute")
async def dashboard(request: Request, db: Session = Depends(get_db)):
    """Render the audit log dashboard."""
    ensure_permission(request, "view_dashboard")
    tenant_id = require_tenant(request)
    query = db.query(AuditLog)
    if tenant_id:
        query = query.filter(AuditLog.tenant_id == tenant_id)
    logs = query.order_by(desc(AuditLog.timestamp)).limit(100).all()
    return templates.TemplateResponse("dashboard.html", {"request": request, "logs": logs})


def _log_detection_background(result: dict, fingerprint: str | None = None):
    """Background task to log detection events without slowing down the API."""
    # legacy callers may pass tenant_id as third arg
    tenant_id = None
    if isinstance(fingerprint, tuple):
        # older callers won't hit this; keep safe
        fingerprint, tenant_id = fingerprint

    db = SessionLocal()
    try:
        # Optionally encrypt redacted prompt before storing when ENCRYPT_LOGS=1
        text = sanitize(result["redacted_text"]) if result.get("redacted_text") else ''
        trace_metadata = {
            "policy_version": os.getenv("POLICY_VERSION", "v1"),
            "request_type": "detect",
            "output_moderation": "not-run",
        }

        if os.getenv('ENCRYPT_LOGS', '0') == '1':
            try:
                keyid, ciphertext = _encrypt(text.encode('utf-8'))
                ciphertext_b64 = base64.b64encode(ciphertext).decode('ascii')
                # store metadata in dedicated columns, keep redacted_prompt non-sensitive
                db_log = AuditLog(
                    user_id="direct-api",
                    tenant_id=tenant_id,
                    redacted_prompt='__encrypted__',
                    redacted_prompt_ciphertext=ciphertext_b64,
                    redacted_prompt_key_id=keyid,
                    redacted_fingerprint=fingerprint,
                    detection_types=result["detections"],
                    trace_metadata=trace_metadata,
                    action="block" if result["block"] else "redact",
                    severity=result["severity"]
                )
            except Exception:
                db_log = AuditLog(
                    user_id="direct-api",
                    tenant_id=tenant_id,
                    redacted_prompt=text,
                    redacted_fingerprint=fingerprint,
                    detection_types=result["detections"],
                    trace_metadata=trace_metadata,
                    action="block" if result["block"] else "redact",
                    severity=result["severity"]
                )
        else:
            db_log = AuditLog(
                user_id="direct-api",
                tenant_id=tenant_id,
                redacted_prompt=text,
                redacted_fingerprint=fingerprint,
                detection_types=result["detections"],
                trace_metadata=trace_metadata,
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
async def detect(request: Request, req: DetectRequest, background_tasks: BackgroundTasks, api_key: str = Depends(get_api_key)):
    """Analyze text for sensitive data (PII, secrets, India-specific IDs)."""
    # Enforce Content-Length/request size limits early to avoid large payload DoS
    try:
        content_length = request.headers.get("content-length")
        if content_length is not None and int(content_length) > settings.MAX_REQUEST_SIZE:
            raise HTTPException(status_code=413, detail="Payload too large")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid Content-Length header") from exc

    # Enforce per-key quota
    if api_key:
        allowed = rate_limiter.allow(api_key)
        if not allowed:
            raise HTTPException(status_code=429, detail="Rate quota exceeded")

    # Enforce tenant context when required.
    tenant_id = require_tenant(request)

    # Compute fingerprint of the incoming text (sha256 hex) for auditing.
    import hashlib
    import time

    fingerprint = hashlib.sha256(req.text.encode("utf-8", errors="ignore")).hexdigest()

    detection_error = False
    start = time.time()
    try:
        result = detect_sensitive(req.text)
    except Exception:
        detection_error = True
        # Detection engine failed. Respect gateway mode.
        gateway_mode = getattr(settings, 'GATEWAY_MODE', os.getenv('GATEWAY_MODE', 'fail_open'))
        if gateway_mode == 'fail_closed':
            if DETECTION_ERROR_COUNTER:
                DETECTION_ERROR_COUNTER.inc()
            raise HTTPException(status_code=503, detail='Detection subsystem unavailable (fail_closed)')
        # fail_open: allow request but mark as undetected
        result = {"detections": [], "block": False, "redact": False, "redacted_text": req.text, "severity": "none"}
    finally:
        duration = time.time() - start
        if REQUEST_COUNTER:
            REQUEST_COUNTER.inc()
        if DETECTION_TOTAL_COUNTER:
            DETECTION_TOTAL_COUNTER.inc()
        if DETECTION_LATENCY:
            DETECTION_LATENCY.observe(duration)
        if REQUEST_LATENCY:
            REQUEST_LATENCY.observe(duration)
        if detection_error and DETECTION_ERROR_COUNTER:
            DETECTION_ERROR_COUNTER.inc()

        breach = _record_detection_slo(duration, detection_error)
        if breach and settings.SLO_ALERT_RECIPIENT:
            background_tasks.add_task(
                send_alert_email,
                entry={
                    "user_id": "system",
                    "severity": "high",
                    "detection_types": "SLO_BREACH",
                    "action_taken": "observe",
                    "timestamp": "now",
                    "redacted_prompt": f"SLO breach p95={breach['p95_ms']}ms err_rate={breach['error_rate']}",
                },
                recipient=settings.SLO_ALERT_RECIPIENT,
            )

    # Auto-log detection events in background (pass tenant).
    if result["detections"]:
        background_tasks.add_task(_log_detection_background, result, (fingerprint, tenant_id))

    return DetectResponse(**result)


@app.post("/log", response_model=LogResponse, dependencies=[Depends(get_api_key)])
@limiter.limit("60/minute")
async def log_event(
    request: Request,
    req: LogRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    api_key: str = Depends(get_api_key)
):
    """Store an audit log entry in SQLite and trigger alerts if needed."""
    # Enforce per-key quota for logging as well
    if api_key:
        allowed = rate_limiter.allow(api_key)
        if not allowed:
            raise HTTPException(status_code=429, detail="Rate quota exceeded")

    tenant_id = require_tenant(request)

    # XSS sanitization
    sanitized_user_id = sanitize(req.user_id)
    sanitized_prompt = sanitize(req.redacted_prompt)
    sanitized_response = sanitize(req.llm_response_redacted) if req.llm_response_redacted else None
    trace_metadata = {
        "policy_version": os.getenv("POLICY_VERSION", "v1"),
        "request_type": "log",
        "output_moderation": "not-run",
    }

    # Run output moderation on provided LLM response when present
    if sanitized_response:
        blocked, reason = moderate_response(sanitized_response, tenant_id)
        trace_metadata["output_moderation"] = reason
        if blocked:
            # escalate action to block if moderation finds secrets
            req.action = "block"
            req.severity = "high"

    # Compute fingerprint of the provided redacted prompt for lookup (do not store raw original)
    import hashlib

    prompt_fingerprint = hashlib.sha256(sanitized_prompt.encode("utf-8", errors="ignore")).hexdigest()

    # Synchronous insert (returns ID immediately). If ENCRYPT_LOGS=1, encrypt and store ciphertext.
    if os.getenv('ENCRYPT_LOGS', '0') == '1':
        try:
            keyid, ciphertext = _encrypt(sanitized_prompt.encode('utf-8'))
            ciphertext_b64 = base64.b64encode(ciphertext).decode('ascii')
            db_log = AuditLog(
                user_id=sanitized_user_id,
                tenant_id=tenant_id,
                redacted_prompt='__encrypted__',
                redacted_prompt_ciphertext=ciphertext_b64,
                redacted_prompt_key_id=keyid,
                redacted_fingerprint=prompt_fingerprint,
                detection_types=req.detection_types,
                trace_metadata=trace_metadata,
                action=req.action,
                severity=req.severity,
                llm_response_redacted=sanitized_response
            )
        except Exception:
            db_log = AuditLog(
                user_id=sanitized_user_id,
                tenant_id=tenant_id,
                redacted_prompt=sanitized_prompt,
                redacted_fingerprint=prompt_fingerprint,
                detection_types=req.detection_types,
                trace_metadata=trace_metadata,
                action=req.action,
                severity=req.severity,
                llm_response_redacted=sanitized_response
            )
    else:
        db_log = AuditLog(
            user_id=sanitized_user_id,
            tenant_id=tenant_id,
            redacted_prompt=sanitized_prompt,
            redacted_fingerprint=prompt_fingerprint,
            detection_types=req.detection_types,
            trace_metadata=trace_metadata,
            action=req.action,
            severity=req.severity,
            llm_response_redacted=sanitized_response
        )

    try:
        db.add(db_log)
        db.commit()
        db.refresh(db_log)
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail="Logging failed") from exc

    # Trigger email alert for HIGH severity in background.
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
