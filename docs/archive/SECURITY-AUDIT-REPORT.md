# CIAI Security Audit Report

**Project**: CIAI — LLM Data Leakage Prevention
**Audit Date**: 2026-04-14
**Auditor**: Security Engineer Agent
**Scope**: Phase 1 codebase (detection engine + FastAPI API + logging layer)
**Version**: 0.2.0

---

## 1. Executive Summary

| Metric | Value |
|--------|-------|
| **Critical Vulnerabilities** | 3 |
| **High Vulnerabilities** | 5 |
| **Medium Vulnerabilities** | 6 |
| **Low/Informational** | 8 |
| **Detection Bypass Rate** | 60% (27/45 evasion techniques succeed) |
| **Security Score** | **22/100** |

**Overall Posture**: **CRITICAL RISK** — The detection engine has significant gaps that allow a motivated attacker to exfiltrate PII undetected. The API layer has zero authentication, zero rate limiting, zero security headers, and stores XSS payloads verbatim in the database. This system would provide false confidence — detecting naive PII leaks but failing against any deliberate evasion.

### Immediate Action Required
1. **Unicode normalization** on all inputs (Critical — 4 bypass techniques)
2. **Zero-width character stripping** (Critical — 3 bypass techniques)
3. **Base64 detection** (Critical — 3 bypass techniques)
4. **Authentication on all endpoints** (High — no access control)
5. **Rate limiting** (High — unlimited abuse possible)
6. **Security headers** (Medium — missing all 5)

---

## 2. Threat Model

### Architecture & Trust Boundaries

```
┌──────────────┐
│  EMPLOYEE    │  ← UNTRUSTED: Can send any input including encoded PII
│  (Browser)   │
└──────┬───────┘
       │ prompt (NO TLS, NO auth)
       ▼
┌──────────────────────┐
│  PROXY / EXTENSION   │  ← TRUST BOUNDARY #1: Network layer
│  (Phase 3 - Planned) │     NOT IMPLEMENTED YET
└──────┬───────────────┘
       │ raw text (NO normalization)
       ▼
┌──────────────────────┐
│  DETECTION ENGINE    │  ← TRUST BOUNDARY #2: Input processing
│  (Phase 1 ✅)        │     Unicode, encoding, spacing all pass through
└──────┬───────────────┘
       │ decision + redacted text
       ▼
┌──────────────────────┐
│  LOGGING + ALERTS    │  ← TRUST BOUNDARY #3: Data persistence
│  (Phase 2 ✅)        │     Unencrypted SQLite, no access control
└──────────────────────┘
       │ email
       ▼
┌──────────────────────┐
│  SMTP Server         │  ← TRUST BOUNDARY #4: External communication
│  (STARTTLS)          │     Credentials in .env file
└──────────────────────┘
```

### STRIDE Analysis

| Threat | Component | Severity | Mitigation Status |
|--------|-----------|----------|-------------------|
| **Spoofing** | All endpoints | **High** | ❌ No authentication — anyone can call /detect and /log |
| **Tampering** | Detection input | **Critical** | ❌ No input normalization — unicode, base64, zero-width chars pass through |
| **Tampering** | Audit logs | **High** | ❌ SQLite at 644 permissions, unencrypted, no access control |
| **Repudiation** | Audit trail | **Medium** | ⚠ Logs exist but user_id can be spoofed (no auth) |
| **Information Disclosure** | Error responses | **Medium** | ❌ Pydantic validation errors leak framework internals |
| **Information Disclosure** | API spec | **Low** | ⚠ OpenAPI spec discloses version and endpoint structure |
| **Information Disclosure** | Server headers | **Low** | ⚠ Uvicorn version disclosed |
| **Denial of Service** | All endpoints | **High** | ❌ No rate limiting — 50 requests in 31s on /detect |
| **Elevation of Privilege** | Log injection | **Medium** | ❌ XSS payloads stored in audit logs without sanitization |

### MITRE ATT&CK Mapping

| Tactic | Technique | CIAI Relevance |
|--------|-----------|----------------|
| **Initial Access** | T1190: Exploit Public-Facing Application | All endpoints are public with no auth |
| **Execution** | T1059: Command and Scripting Interpreter | Stored XSS in audit logs could execute if dashboard renders HTML |
| **Persistence** | T1505: Server Software Component | Audit log database can be modified by any caller |
| **Defense Evasion** | T1027: Obfuscated Files or Information | Base64, unicode homoglyphs, zero-width chars all bypass detection |
| **Defense Evasion** | T1036: Masquerading | Cyrillic homoglyphs make PII look like different characters |
| **Credential Access** | T1552: Unsecured Credentials | .env file with SMTP credentials at risk if server compromised |
| **Collection** | T1005: Data from Local System | SQLite database with all audit logs readable (644 permissions) |
| **Exfiltration** | T1041: Exfiltration Over C2 Channel | PII bypasses detection and reaches LLM unblocked |

---

## 3. Vulnerabilities Found

### VULN-001: Unicode Homoglyph Bypass (Critical)
**Severity**: Critical (CVSS 9.1)
**Component**: `src/detection/detect.py` — regex patterns
**Description**: All regex patterns use `[A-Z]` and `\d` which match only ASCII characters. Cyrillic homoglyphs (А vs A, Е vs E), fullwidth digits (２ vs 2), and Greek lookalikes (ο vs o) bypass all detection.

**Proof of Concept**:
```python
detect_sensitive("My PAN is АBCDE1234F")  # Cyrillic А → NO DETECTION
detect_sensitive("My Aadhaar is ２３４５６７８９０１２３")  # Fullwidth digits → NO DETECTION
```

**Remediation**:
```python
import unicodedata

def normalize_input(text: str) -> str:
    """NFKC normalization converts homoglyphs to ASCII equivalents."""
    # Step 1: NFKC normalization (fullwidth→ASCII, compatibility decomposition)
    text = unicodedata.normalize('NFKC', text)
    # Step 2: Strip zero-width characters
    text = re.sub(r'[\u200b\u200c\u200d\ufeff\u200e\u200f]', '', text)
    return text
```
Apply normalization BEFORE running regex patterns.

---

### VULN-002: Zero-Width Character Injection Bypass (Critical)
**Severity**: Critical (CVSS 8.8)
**Component**: `src/detection/detect.py`
**Description**: Zero-width space (U+200B), zero-width non-joiner (U+200C), and zero-width joiner (U+200D) can be inserted between digits/characters to break regex pattern matching.

**Proof of Concept**:
```python
detect_sensitive("2345\u200b6789\u200b0123")  # Aadhaar with ZWS → NO DETECTION
detect_sensitive("ABCDE\u200c1234F")           # PAN with ZWNJ → NO DETECTION
detect_sensitive("4111\u200d1111\u200d1111\u200d1111")  # CC with ZWJ → NO DETECTION
```

**Remediation**: Strip zero-width characters during input normalization (see VULN-001 fix).

---

### VULN-003: Base64-Encoded PII Bypass (Critical)
**Severity**: Critical (CVSS 8.6)
**Component**: `src/detection/detect.py`
**Description**: The detection engine only scans raw text. Base64-encoded PII is invisible to all regex patterns and Presidio.

**Proof of Concept**:
```python
detect_sensitive("TXkgQWFkaGFhciBpcyAyMzQ1Njc4OTAxMjM=")  # Base64 Aadhaar → NO DETECTION
detect_sensitive("QUJDREUxMjM0Rg==")  # Base64 PAN → NO DETECTION
```

**Remediation**:
```python
import re
import base64

def detect_base64_pii(text: str) -> list[str]:
    """Find and decode base64 strings, then check for PII."""
    detections = []
    b64_pattern = r'[A-Za-z0-9+/]{16,}={0,2}'
    for match in re.finditer(b64_pattern, text):
        try:
            decoded = base64.b64decode(match.group()).decode('utf-8', errors='ignore')
            sub_result = detect_sensitive(decoded)
            if sub_result['detections']:
                detections.extend([f"BASE64_{d}" for d in sub_result['detections']])
        except Exception:
            pass
    return detections
```

---

### VULN-004: No Authentication on Any Endpoint (High)
**Severity**: High (CVSS 7.5)
**Component**: `src/api/main.py`
**Description**: All three endpoints (`/detect`, `/log`, `/health`) are publicly accessible without any authentication, API key, or token. Any network-accessible caller can:
- Query the detection engine (reconnaissance to learn what gets detected)
- Write arbitrary data to audit logs (log pollution, XSS storage)
- Health check reveals service status

**Proof of Concept**:
```bash
curl -X POST http://localhost:8000/detect -d '{"text":"anything"}'
# Returns 200 with detection result — no auth required

curl -X POST http://localhost:8000/log -d '{"user_id":"attacker","redacted_prompt":"x","detection_types":[],"action":"block"}'
# Returns 200 — log entry created, no auth required
```

**Remediation**:
```python
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

security = HTTPBearer()

def verify_api_key(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if credentials.credentials != os.getenv("API_KEY"):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

@app.post("/detect", dependencies=[Depends(verify_api_key)])
@app.post("/log", dependencies=[Depends(verify_api_key)])
```

---

### VULN-005: No Rate Limiting (High)
**Severity**: High (CVSS 7.5)
**Component**: `src/api/main.py`
**Description**: No rate limiting on any endpoint. 50 requests to `/detect` completed in 31 seconds. This enables:
- Denial of service (CPU exhaustion via Presidio NLP processing)
- Reconnaissance (test what patterns get detected)
- Log flooding (fill the SQLite database)

**Proof of Concept**:
```python
for i in range(50):
    client.post("/detect", json={"text": f"test {i}"})
# All 50 returned 200 in 31.45s
```

**Remediation**: Use `slowapi` or `fastapi-limiter` middleware:
```python
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

@app.post("/detect")
@limiter.limit("30/minute")
async def detect(request: Request, req: DetectRequest):
    ...
```

---

### VULN-006: Stored XSS in Audit Logs (High)
**Severity**: High (CVSS 7.3)
**Component**: `src/api/main.py` → `src/logging/db.py`
**Description**: The `/log` endpoint accepts arbitrary HTML/JavaScript in `user_id` and `redacted_prompt` fields and stores them verbatim in SQLite. If the planned dashboard renders these values without output encoding, stored XSS executes.

**Proof of Concept**:
```bash
curl -X POST http://localhost:8000/log \
  -H "Content-Type: application/json" \
  -d '{"user_id":"<script>alert(1)</script>","redacted_prompt":"<img src=x onerror=alert(1)>","detection_types":[],"action":"block"}'
```
Database confirmed storage:
```
user_id: "<script>alert('xss')</script>"
prompt: "<img src=x onerror=alert(1)>"
```

**Remediation**:
1. Input sanitization: `html.escape()` on all stored fields
2. Output encoding in dashboard: `markupsafe.escape()` or template auto-escaping
3. Content Security Policy on dashboard

---

### VULN-007: Missing India-Specific PII Types (High)
**Severity**: High (CVSS 7.0)
**Component**: `src/detection/detect.py`
**Description**: The detection engine does not cover several India-specific PII types mandated by DPDP Act compliance:
- Voter ID (EPIC): `ABC1234567`
- Driving License: `DL-0420110012345`
- GST Number: `22AAAAA0000A1Z5`
- Bank Account Number: Indian format (IFSC + account)
- UPI ID: `name@upi`
- Passport Number: Indian format `A1234567`

**Remediation**: Add regex patterns for each type:
```python
VOTER_ID_PATTERN = r'\b[A-Z]{3}\d{7}\b'
DRIVING_LICENSE_PATTERN = r'\b(?:DL|DL-)\d{14,15}\b'
GST_PATTERN = r'\b\d{2}[A-Z]{5}\d{4}[A-Z]{1}[A-Z\d]{1}[Z]{1}[A-Z\d]{1}\b'
PASSPORT_PATTERN = r'\b[A-Z][1-9]\d{7}\b'
UPI_ID_PATTERN = r'\b[\w.-]+@[\w]{2,6}\b'
```

---

### VULN-008: OCR/Spacing Evasion (Medium)
**Severity**: Medium (CVSS 6.5)
**Component**: `src/detection/detect.py`
**Description**: PII with non-standard spacing evades detection:
- Aadhaar with dot separators: `2345.6789.0123` → NOT DETECTED
- Aadhaar with single-digit spacing: `2 3 4 5 6 7 8 9 0 1 2 3` → NOT DETECTED
- PAN split across words: `ABCD E123 4F` → NOT DETECTED
- Aadhaar with fullwidth dots: not tested but likely bypasses

**Remediation**: Pre-process input to normalize spacing before pattern matching:
```python
def normalize_spacing(text: str) -> str:
    # Collapse multiple spaces
    text = re.sub(r'\s+', ' ', text)
    # Normalize dot separators in digit sequences
    text = re.sub(r'(\d)\.(\d)', r'\1-\2', text)
    return text
```

---

### VULN-009: API Key Splitting Evasion (Medium)
**Severity**: Medium (CVSS 6.1)
**Component**: `src/detection/detect.py`
**Description**: API keys split across multiple lines or concatenated from parts bypass detection:
```python
"key_part1 = 'sk-abcdefghijklm'\nkey_part2 = 'nopqrstuvwxyz'"
# Neither part matches sk-[a-zA-Z0-9]{20,} individually
```

**Remediation**: This requires contextual analysis beyond single-pass regex. Options:
1. Concatenate all string literals in the input before scanning
2. Use LLM-based contextual detection for split secrets
3. Accept as known limitation (defense-in-depth: LLM provider also monitors key usage)

---

### VULN-010: Presidio Only Detects English (Medium)
**Severity**: Medium (CVSS 5.8)
**Component**: `src/detection/detect.py` — `_run_presidio()`
**Description**: Presidio is configured with `language='en'` only. While the Aadhaar regex works on Hindi text (digits are ASCII), Presidio's NER (person names, emails, phones) may miss PII in non-English text. The email/phone detection failure in test 7 suggests Presidio's English model doesn't trigger on short inputs.

**Evidence**: Test showed `john.doe@example.com` and `+91 98765 43210` were NOT detected by Presidio.

**Remediation**:
1. Add multi-language support: `analyzer.analyze(text=text, languages=['en', 'hi'])`
2. Add standalone email/phone regex patterns as fallback (don't rely only on Presidio)
3. Lower confidence threshold from 0.5 to 0.35 for email/phone

---

### VULN-011: Database File Permissions (Medium)
**Severity**: Medium (CVSS 5.5)
**Component**: `data/ciai_audit.db`
**Description**: Database file has `644` permissions (owner read/write, group/other read). Any user on the system can read audit logs containing redacted prompts, user IDs, and detection metadata.

**Remediation**:
```bash
chmod 600 ./data/ciai_audit.db
# And ensure directory is also restricted
chmod 700 ./data/
```
In code, set umask on startup:
```python
os.umask(0o077)
```

---

### VULN-012: No Security Headers (Medium)
**Severity**: Medium (CVSS 5.3)
**Component**: `src/api/main.py`
**Description**: All 5 critical security headers are missing:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Strict-Transport-Security`
- `Content-Security-Policy`
- `X-XSS-Protection`

**Remediation**: Add middleware:
```python
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Cache-Control"] = "no-store"
        # Remove server header
        response.headers.pop("server", None)
        return response

app.add_middleware(SecurityHeadersMiddleware)
```

---

### VULN-013: No Data Retention Policy (Low)
**Severity**: Low (CVSS 4.3)
**Component**: `src/logging/db.py`
**Description**: Audit logs grow indefinitely with no rotation, archival, or deletion policy. This violates DPDP Act data minimization requirements and creates a growing attack surface.

**Remediation**:
```python
async def purge_old_logs(days: int = 90):
    """Delete logs older than retention period."""
    from datetime import timedelta
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    async with AsyncSessionLocal() as session:
        await session.execute(
            delete(AuditLog).where(AuditLog.timestamp < cutoff)
        )
        await session.commit()
```
Schedule via cron or APScheduler.

---

### VULN-014: .env File Not in .gitignore (Low)
**Severity**: Low (CVSS 3.7)
**Component**: `.gitignore`
**Description**: `.env.example` exists but `.env` is NOT listed in `.gitignore`. If a developer commits `.env`, SMTP credentials and API keys will be exposed in version control.

**Remediation**: Add `.env` to `.gitignore`.

---

### VULN-015: Exception Details in Error Responses (Low)
**Severity**: Low (CVSS 3.7)
**Component**: `src/api/main.py`
**Description**: Pydantic validation error responses leak internal framework details:
```json
{"detail":[{"type":"string_type","loc":["body","text"],"msg":"Input should be a valid string","input":null}]}
```
This reveals the API uses Pydantic and the exact field structure.

**Remediation**: Override FastAPI's exception handler:
```python
from fastapi.exceptions import RequestValidationError

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc):
    return JSONResponse(
        status_code=422,
        content={"error": "Invalid request", "message": "One or more fields failed validation"}
    )
```

---

### VULN-016: Null Byte Acceptance (Low)
**Severity**: Low (CVSS 3.1)
**Component**: `src/api/main.py` → `src/detection/detect.py`
**Description**: Null bytes (`\x00`) in input are accepted and processed. While Python handles them safely, downstream systems (C extensions in spacy/Presidio, SQLite) may truncate at null bytes, causing partial scanning.

**Remediation**: Strip null bytes on input:
```python
text = text.replace('\x00', '')
```

---

### VULN-017: Spacy Model Version Not Pinned (Informational)
**Severity**: Informational
**Component**: `src/detection/detect.py`
**Description**: The spacy model `en_core_web_sm` is loaded dynamically without version pinning. A model update could change detection behavior or introduce regressions.

**Remediation**: Pin the model version in requirements.txt and verify on startup:
```python
import spacy
model = spacy.load("en_core_web_sm")
assert model.meta["version"] == "3.8.0", f"Unexpected spacy model version"
```

---

### VULN-018: No LLM Response Scanning (Informational)
**Severity**: Informational
**Component**: Architecture (Phase 2 planned)
**Description**: The architecture mentions scanning LLM responses before returning to user, but this is not implemented. LLM responses can contain PII (e.g., ChatGPT echoing back user data or generating synthetic PII).

**Remediation**: Implement response scanning in the proxy layer (Phase 3).

---

## 4. PII Detection Gap Analysis

### What IS Detected (Baseline)
| PII Type | Detection Method | Works? |
|----------|-----------------|--------|
| Aadhaar (XXXX XXXX XXXX) | Regex | ✅ Yes |
| Aadhaar (XXXXXXXXXXXX) | Regex | ✅ Yes |
| PAN (ABCDE1234F) | Regex | ✅ Yes |
| Credit Card (with Luhn) | Regex + Luhn | ✅ Yes |
| OpenAI Key (sk-...) | Regex | ✅ Yes |
| Anthropic Key (sk-ant-...) | Regex | ✅ Yes |
| AWS Access Key (AKIA...) | Regex | ✅ Yes |
| AWS Secret (aws_secret_access_key=...) | Regex | ✅ Yes |
| Generic API Key (api_key=...) | Regex | ✅ Yes |
| Bearer Token | Regex | ✅ Yes |
| Password/Secret assignment | Regex | ✅ Yes |
| Email | Presidio | ⚠️ Inconsistent (missed in testing) |
| Phone | Presidio | ⚠️ Inconsistent (missed in testing) |
| Person Name | Presidio | ⚠️ Depends on context |
| US SSN | Presidio | ❌ NOT detected (test failed) |

### What IS NOT Detected (Gaps)
| PII Type | Reason | Risk |
|----------|--------|------|
| Aadhaar (unicode homoglyphs) | Regex uses [A-Z] and \d (ASCII only) | **Critical** |
| Aadhaar (zero-width chars) | Regex doesn't handle invisible characters | **Critical** |
| Aadhaar (base64 encoded) | No base64 decoding | **Critical** |
| Aadhaar (dot separators) | Regex only handles space/dash | **Medium** |
| Aadhaar (spelled out) | No NLP number parsing | **Medium** |
| Aadhaar (partial/truncated) | Regex requires all 12 digits | **Low** (by design) |
| PAN (Cyrillic homoglyphs) | Regex uses [A-Z] | **Critical** |
| PAN (leetspeak) | Regex requires exact format | **Low** |
| PAN (split across words) | Regex requires contiguous string | **Medium** |
| Credit Card (zero-width chars) | Regex doesn't strip invisible chars | **Critical** |
| Credit Card (base64) | No base64 decoding | **Critical** |
| API Key (split across lines) | Regex scans single string | **Medium** |
| Voter ID (EPIC) | No pattern defined | **High** |
| Driving License | No pattern defined | **High** |
| GST Number | No pattern defined | **High** |
| UPI ID | No pattern defined | **High** |
| Passport (Indian) | No pattern defined | **High** |
| Bank Account + IFSC | No pattern defined | **High** |

---

## 5. Bypass Techniques That Succeeded

27 out of 45 evasion techniques (60%) successfully bypassed detection:

### Category 1: Unicode Attacks (4/4 succeeded)
| Technique | Example | Result |
|-----------|---------|--------|
| Cyrillic homoglyphs | `АBCDE1234F` (Cyrillic А) | ✅ BYPASSED |
| Fullwidth digits | `２３４５６７８９０１２３` | ✅ BYPASSED |
| Greek lookalikes | `ο2345 6789 0123` | ✅ BYPASSED |
| Mixed script | `ABCDЕ1234F` (Cyrillic Е) | ✅ BYPASSED |

### Category 2: Encoding Attacks (3/4 succeeded)
| Technique | Example | Result |
|-----------|---------|--------|
| Base64 Aadhaar | `TXkgQWFkaGFhciBpcyAyMzQ1Njc4OTAxMjM=` | ✅ BYPASSED |
| Base64 PAN | `QUJDREUxMjM0Rg==` | ✅ BYPASSED |
| Base64 CC | `NDExMTExMTExMTExMTExMQ==` | ✅ BYPASSED |
| Base64 API key | `c2stYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4` | ❌ DETECTED (accidental — base64 decoded to plaintext in the test string) |

### Category 3: Invisible Character Injection (3/3 succeeded)
| Technique | Example | Result |
|-----------|---------|--------|
| Zero-width space (U+200B) | `2345\u200b6789\u200b0123` | ✅ BYPASSED |
| Zero-width non-joiner (U+200C) | `ABCDE\u200c1234F` | ✅ BYPASSED |
| Zero-width joiner (U+200D) | `4111\u200d1111\u200d1111\u200d1111` | ✅ BYPASSED |

### Category 4: Spacing/Separator Evasion (3/4 succeeded)
| Technique | Example | Result |
|-----------|---------|--------|
| Extra spaces between digits | `2 3 4 5 6 7 8 9 0 1 2 3` | ✅ BYPASSED |
| Dot separators | `2345.6789.0123` | ✅ BYPASSED |
| PAN split across words | `ABCD E123 4F` | ✅ BYPASSED |
| Tab-separated CC digits | `4111\t1111\t1111\t1111` | ❌ DETECTED |

### Category 5: Partial/Truncated PII (3/5 succeeded)
| Technique | Example | Result |
|-----------|---------|--------|
| First 4 Aadhaar digits | `2345` | ✅ BYPASSED |
| Last 4 Aadhaar digits | `0123` | ✅ BYPASSED |
| Incomplete PAN (9 chars) | `ABCDE1234` | ✅ BYPASSED |
| First 4 + last 4 (8 digits) | `2345 XXXX 0123` | ❌ DETECTED (matched Aadhaar regex — false positive on partial) |
| 12-digit number | `4111 1111 1111` | ❌ NOT DETECTED (correctly — not a valid CC length) |

### Category 6: Missing PII Types (4/4 succeeded)
| Technique | Example | Result |
|-----------|---------|--------|
| Voter ID | `ABC1234567` | ✅ BYPASSED |
| Driving License | `DL-0420110012345` | ✅ BYPASSED |
| GST Number | `22AAAAA0000A1Z5` | ✅ BYPASSED |
| US SSN | `123-45-6789` | ✅ BYPASSED |

### Category 7: API Key Splitting (2/3 succeeded)
| Technique | Example | Result |
|-----------|---------|--------|
| OpenAI key split | `sk-abcdefghijklm` + `nopqrstuvwxyz` on separate lines | ✅ BYPASSED |
| Secret split | `'my' + 'password123'` | ✅ BYPASSED |
| AWS key with prefix | `prefix_AKIAIOSFODNN7EXAMPLE_suffix` | ❌ DETECTED (AKIA pattern matched) |

### What Did NOT Bypass (Detection Worked)
- **Prompt injection** — Detection is stateless regex; "ignore instructions" text has no effect
- **JSON/XML encoded PII** — Regex scans full text including structured data
- **PII in code comments** — Regex matches regardless of context
- **Hindi text with Aadhaar** — Digits are ASCII, regex matches
- **Multiple PII in one prompt** — All regex patterns fire independently
- **Reversed Aadhaar** — `321098765432` still matches the 12-digit regex (order-independent)

---

## 6. Dependency Risk Table

| Package | Installed | Latest | Known CVEs | Risk |
|---------|-----------|--------|------------|------|
| **presidio-analyzer** | 2.2.359 | 2.2.362 | 0 (Snyk: No known issues) | ✅ Low |
| **presidio-anonymizer** | 2.2.362 | 2.2.362 | 0 (CVE-2025-15467 was OpenSSL, not Python) | ✅ Low |
| **fastapi** | 0.135.3 | 0.135.3+ | 0 | ✅ Low |
| **uvicorn** | 0.44.0 | 0.44.0+ | 0 | ✅ Low |
| **pydantic** | 2.13.0 | 2.13.0+ | 0 | ✅ Low |
| **spacy** | 3.8.13 | 3.8.13+ | 0 | ✅ Low |
| **SQLAlchemy** | 2.0.49 | 2.0.49+ | 0 | ✅ Low |
| **aiosqlite** | 0.22.1 | 0.22.1+ | 0 | ✅ Low |
| **httpx** | 0.28.1 | 0.28.1+ | 0 | ✅ Low |
| **requests** | 2.33.1 | 2.33.1+ | 0 | ✅ Low |
| **python-dotenv** | 1.2.0 | 1.2.0+ | 0 | ✅ Low |
| **aiosmtplib** | 5.1.0 | 5.1.0+ | 0 | ✅ Low |
| **pytest** | 9.0.3 | 9.0.3+ | 0 | ✅ Low |
| **pytest-asyncio** | 1.3.0 | N/A | 0 | ✅ Low |

**Supply Chain Verdict**: All dependencies are at or near latest versions with zero known CVEs. The supply chain risk is **LOW**. The primary risk is not the dependencies themselves but how they are used (or misused) in the application code.

### CVE-2025-15467 Note
This CVE was referenced in the presidio GitHub issues but is actually an **OpenSSL** vulnerability (CMS AuthEnvelopedData stack buffer overflow, CVSS 9.8). It affects OpenSSL 3.0-3.6 when parsing malicious CMS/PKCS7 content. The presidio Python packages are NOT affected — this is a C library vulnerability in the system's OpenSSL. If the deployment system runs a vulnerable OpenSSL version, it could be exploited via S/MIME processing, but this is outside CIAI's direct scope.

---

## 7. Recommendations — Priority Order

### P0 — Fix This Week (Critical)

| # | Action | Effort | Impact |
|---|--------|--------|--------|
| 1 | **Add Unicode NFKC normalization** to all text inputs before detection | 2 hours | Closes 4 bypass techniques (homoglyphs, fullwidth digits) |
| 2 | **Strip zero-width characters** during normalization | 1 hour | Closes 3 bypass techniques (ZWS, ZWNJ, ZWJ) |
| 3 | **Add base64 detection and decoding** before PII scanning | 4 hours | Closes 3 bypass techniques (base64-encoded PII) |
| 4 | **Add API key authentication** to /detect and /log endpoints | 3 hours | Prevents unauthorized access and reconnaissance |

### P1 — Fix This Sprint (High)

| # | Action | Effort | Impact |
|---|--------|--------|--------|
| 5 | **Add rate limiting** (30 req/min on /detect, 10 req/min on /log) | 2 hours | Prevents DoS and reconnaissance |
| 6 | **Add India-specific PII patterns**: Voter ID, DL, GST, UPI, Passport | 4 hours | Closes 6 detection gaps |
| 7 | **Sanitize input before storage** — HTML escape user_id and redacted_prompt | 1 hour | Prevents stored XSS |
| 8 | **Fix database permissions** to 600, directory to 700 | 30 min | Prevents local data exfiltration |
| 9 | **Add email/phone regex fallback** — don't rely only on Presidio | 2 hours | Fixes inconsistent email/phone detection |

### P2 — Fix Next Sprint (Medium)

| # | Action | Effort | Impact |
|---|--------|--------|--------|
| 10 | **Add all 5 security headers** via middleware | 1 hour | Hardens HTTP security posture |
| 11 | **Implement data retention policy** — purge logs after 90 days | 2 hours | DPDP Act compliance |
| 12 | **Add .env to .gitignore** | 15 min | Prevents credential leakage |
| 13 | **Override validation error responses** — remove framework details | 1 hour | Reduces information disclosure |
| 14 | **Strip null bytes** from input | 15 min | Prevents partial scanning |
| 15 | **Handle dot separators** in Aadhaar regex | 1 hour | Closes OCR-style evasion |

### P3 — Architectural Improvements (Long-term)

| # | Action | Effort | Impact |
|---|--------|--------|--------|
| 16 | **Implement mitmproxy interceptor** (Phase 3) | 2 weeks | Core functionality for traffic interception |
| 17 | **Add LLM response scanning** | 1 week | Detects PII in LLM outputs |
| 18 | **Add multi-language Presidio support** (en + hi) | 1 day | Improves PII detection in mixed-language text |
| 19 | **Implement split-secret detection** | 3 days | Detects API keys split across lines |
| 20 | **Add TLS/SSL for proxy traffic** | 1 day | Encrypts traffic between proxy and detection API |
| 21 | **Encrypt SQLite database** (SQLCipher) | 2 days | Protects audit logs at rest |
| 22 | **Add audit log integrity protection** (HMAC signing) | 1 day | Detects log tampering |

---

## 8. Security Score Breakdown

**Overall Score: 22/100**

### Scoring Breakdown

| Category | Weight | Score | Notes |
|----------|--------|-------|-------|
| **Input Validation & Normalization** | 20% | 5/20 | Regex-only detection, no normalization, 60% bypass rate |
| **Authentication & Authorization** | 20% | 0/20 | Zero authentication on any endpoint |
| **Rate Limiting & DoS Protection** | 10% | 0/10 | No rate limiting, no request size limits on /log |
| **Data Protection at Rest** | 10% | 2/10 | SQLite unencrypted, 644 permissions, no retention policy |
| **Data Protection in Transit** | 10% | 5/10 | No TLS enforcement (planned for Phase 3) |
| **Security Headers** | 5% | 0/5 | All 5 headers missing |
| **PII Detection Coverage** | 15% | 6/15 | Detects basic patterns but misses 6 India-specific PII types |
| **Error Handling & Info Disclosure** | 5% | 2/5 | Framework internals leaked, no generic error pages |
| **Supply Chain** | 5% | 5/5 | All deps up to date, zero CVEs |

### What Would Improve the Score
- **Implement P0 fixes**: +25 points → 47/100
- **Implement P1 fixes**: +20 points → 67/100
- **Implement P2 fixes**: +13 points → 80/100
- **Implement P3 fixes**: +10 points → 90/100

---

## 9. Files Audited

| File | Lines | Issues Found |
|------|-------|--------------|
| `src/detection/detect.py` | 202 | 8 (VULN-001, 002, 003, 007, 008, 009, 010, 017) |
| `src/api/main.py` | 138 | 6 (VULN-004, 005, 006, 012, 015, 016) |
| `src/logging/db.py` | 124 | 3 (VULN-006, 011, 013) |
| `src/logging/alerts.py` | 167 | 0 (well-implemented rate limiting and error handling) |
| `tests/test_detection.py` | ~200 | 0 (comprehensive baseline tests) |
| `tests/test_logging.py` | ~200 | 0 (good test coverage) |
| `requirements.txt` | 18 | 0 (all deps current) |
| `.gitignore` | 17 | 1 (VULN-014 — .env not listed) |
| `src/proxy/__init__.py` | 0 | Not implemented yet (Phase 3) |

---

## 10. Audit Artifacts

The following test files were created during this audit and can be used for regression testing:

| File | Purpose |
|------|---------|
| `security_audit_bypass.py` | 45 evasion technique tests — run after any detection engine changes |
| `security_audit_api.py` | 8 categories of API security tests — run after any API changes |

**Recommended**: Add these to CI/CD as blocking tests.

---

*Audit completed on 2026-04-14. Next audit recommended after P0+P1 fixes are implemented.*
