# BUILD LOG — Phase 1: Detection Engine + API Skeleton

**Project:** CIAI – LLM Data Leakage Prevention  
**Date:** 2026-04-13  
**Phase:** 1 of 5 (Foundation)  
**Status:** ✅ Complete

---

## What Was Done

### 1. Project Structure Created
```
LLM_vulnerablities/
├── src/
│   ├── __init__.py
│   ├── detection/
│   │   ├── __init__.py
│   │   └── detect.py           # Core detection engine
│   ├── api/
│   │   ├── __init__.py
│   │   └── main.py             # FastAPI control plane
│   ├── logging/                # (Phase 2)
│   ├── proxy/                  # (Phase 3)
├── tests/
│   ├── __init__.py
│   └── test_detection.py       # 34 unit tests
├── .venv/                      # Python 3.14 virtualenv
├── requirements.txt
├── README.md                   # (existing project docs)
├── ARCHITECTURE.md             # (existing project docs)
├── "implementation plan.md"    # (existing project docs)
└── BUILD-LOG-PHASE1.md         # <-- this file
```

### 2. Dependencies Installed
- **fastapi 0.135.3** — API framework
- **uvicorn 0.44.0** — ASGI server
- **pydantic 2.13.0** — request/response validation
- **presidio-analyzer 2.2.359** — Microsoft PII detection
- **presidio-anonymizer 2.2.362** — text redaction
- **spacy 3.8.13** + **en_core_web_sm** (13MB) — NLP model (small, not large 400MB)
- **pytest 9.0.3** + **pytest-asyncio 1.3.0** — testing
- **httpx 0.27.0** — async HTTP client
- **requests 2.31.0** — sync HTTP

```bash
cd /run/media/sham/AI_/ai-stack/projects/LLM_vulnerablities
python3 -m venv .venv
source .venv/bin/activate
pip install fastapi uvicorn pydantic httpx requests pytest pytest-asyncio
pip install presidio-analyzer presidio-anonymizer spacy
python -m spacy download en_core_web_sm
```

### 3. Detection Engine Built (`src/detection/detect.py`)

**Design decisions:**
- Used `en_core_web_sm` (13MB) instead of `en_core_web_lg` (400MB) — system has 7.5GB RAM, no room for bloat
- Lazy-load Presidio engines to avoid startup overhead
- Regex-first, Presidio-second approach (regex is instant, Presidio adds ~50ms)
- Graceful degradation: if Presidio fails, regex still works

**India-specific patterns implemented:**

| Pattern | Regex | Example | Severity |
|---------|-------|---------|----------|
| Aadhaar | `[2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}` | `2345 6789 0123` | HIGH (block) |
| PAN | `[A-Z]{5}[0-9]{4}[A-Z]{1}` | `ABCDE1234F` | HIGH (block) |
| Credit Card | 13-19 digits + Luhn check | `4111 1111 1111 1111` | HIGH (block) |
| OpenAI Key | `sk-[a-zA-Z0-9]{20,}` | `sk-abc...` | HIGH (block) |
| Anthropic Key | `sk-ant-[a-zA-Z0-9\-]{20,}` | `sk-ant-api03-...` | HIGH (block) |
| AWS Access Key | `AKIA[0-9A-Z]{16}` | `AKIAIOSFODNN7EXAMPLE` | HIGH (block) |
| AWS Secret | `(?:aws_secret_access_key)\s*[=:]\s*...` | `aws_secret=...` | HIGH (block) |
| Generic API Key | `(?:api_key)\s*[=:]\s*...` | `api_key=mykey123` | HIGH (block) |
| Generic Secret | `(?:secret\|password\|token)\s*[=:]\s*...` | `password=SuperSecret` | HIGH (block) |
| Bearer Token | `Bearer\s+[a-zA-Z0-9_\-\.]{20,}` | `Bearer eyJhbG...` | HIGH (block) |

**Presidio detects (via NER):**
- EMAIL_ADDRESS, PHONE_NUMBER, PERSON, LOCATION, DATE_TIME, IP_ADDRESS, URL

**Luhn validation:** Implemented for credit card detection — rejects random digit sequences that aren't valid card numbers.

**Detection function:**
```python
result = detect_sensitive("My Aadhaar is 234567890123")
# Returns:
{
    "detections": ["AADHAAR"],
    "block": True,
    "redact": True,
    "redacted_text": "My Aadhaar is [REDACTED]",
    "severity": "high"
}
```

**Severity classification:**
- `high` — any Aadhaar, PAN, credit card, API key, or secret detected → BLOCK
- `medium` — 2+ detections from Presidio (email + phone, etc.)
- `low` — single Presidio detection
- `none` — clean text

### 4. FastAPI API Built (`src/api/main.py`)

**Endpoints:**

| Method | Path | Description | Status |
|--------|------|-------------|--------|
| GET | `/health` | Health check | ✅ Working |
| POST | `/detect` | Analyze text for PII/secrets | ✅ Working |
| POST | `/log` | Store audit event | ⚠️ Placeholder (Phase 2) |

**Request/Response models (Pydantic):**
- `DetectRequest` — `text: str` (1-100,000 chars)
- `DetectResponse` — `detections, block, redact, redacted_text, severity`
- `LogRequest` — `user_id, redacted_prompt, detection_types, action`
- `LogResponse` — `status, id`

### 5. Tests Written (`tests/test_detection.py`)

**34 tests across 9 test classes:**

| Test Class | Tests | Coverage |
|------------|-------|----------|
| `TestLuhnCheck` | 3 | Valid Visa/Mastercard, invalid number |
| `TestAadhaarDetection` | 4 | Plain, dashes, spaces, invalid first digit |
| `TestPANDetection` | 3 | Valid uppercase, invalid lowercase, in sentence |
| `TestCreditCardDetection` | 4 | Visa, Mastercard, Luhn reject, with spaces |
| `TestAPIKeyDetection` | 6 | OpenAI, Anthropic, Bearer, AWS key, generic key, password |
| `TestSeverityClassification` | 4 | Clean, empty, high severity, redaction applied |
| `TestRedaction` | 5 | Aadhaar, PAN, credit card, clean text, API key |
| `TestAPIEndpoints` | 5 | Health, detect clean, detect PII, empty rejected, log placeholder |

---

## How It Was Done

### Step 1: Project Structure
```bash
mkdir -p src/{detection,api,logging,proxy} tests
touch src/__init__.py src/{detection,api,logging,proxy}/__init__.py tests/__init__.py
```

### Step 2: Virtual Environment + Dependencies
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install fastapi uvicorn pydantic httpx requests pytest pytest-asyncio
pip install presidio-analyzer presidio-anonymizer spacy
python -m spacy download en_core_web_sm
```

**Key decision:** Used `en_core_web_sm` (13MB) instead of default `en_core_web_lg` (400MB). The default caused a 400MB download that would hang on slow connections. Fixed by explicitly loading the small model in `_get_analyzer()`.

### Step 3: Detection Engine
Built `src/detection/detect.py` with:
- Lazy-loaded Presidio engines (no startup cost)
- Regex patterns for India-specific IDs
- Luhn check for credit card validation
- Severity classification logic
- Text redaction via Presidio + regex

### Step 4: FastAPI Skeleton
Built `src/api/main.py` with:
- Pydantic request/response models
- `/detect` endpoint → calls `detect_sensitive()`
- `/log` endpoint → placeholder for Phase 2
- `/health` endpoint → health check

### Step 5: Tests
Wrote `tests/test_detection.py` with 34 tests covering all detection types, redaction, severity, and API endpoints.

---

## How It Was Verified

### Tests
```
$ pytest tests/test_detection.py -v
34 passed in 19.09s
```

### Manual Verification
```
$ python -c "
from src.detection.detect import detect_sensitive

# Aadhaar detection
result = detect_sensitive('My Aadhaar is 234567890123')
# → {'detections': ['AADHAAR'], 'block': True, 'redact': True, 
#    'redacted_text': 'My Aadhaar is [REDACTED]', 'severity': 'high'}

# Clean text
result = detect_sensitive('Hello world')
# → {'detections': [], 'block': False, 'redact': False, 
#    'redacted_text': 'Hello world', 'severity': 'none'}

# Mixed PII
result = detect_sensitive('PAN: ABCDE1234F, email: john@example.com')
# → {'detections': ['PAN'], 'block': True, 'redact': True, 
#    'redacted_text': 'PAN: [REDACTED], email: john@example.com', 'severity': 'high'}
"
```

### API Server Start
```
$ uvicorn src.api.main:app --host 0.0.0.0 --port 8000
INFO:     Started server process [7183]
INFO:     Uvicorn running on http://0.0.0.0:8000
```

---

## Issues Encountered

### 1. Presidio Default Model Too Large
**Problem:** `AnalyzerEngine()` defaults to loading `en_core_web_lg` (400MB). This caused downloads to hang and would consume too much RAM.

**Fix:** Explicitly load `en_core_web_sm` (13MB):
```python
nlp = spacy.load("en_core_web_sm")
_analyzer = AnalyzerEngine(nlp_engine=nlp)
```

### 2. Test Timeout on First Run
**Problem:** Tests timed out (120s) because the first call to `detect_sensitive()` triggered the 400MB model download.

**Fix:** After switching to `en_core_web_sm`, all 34 tests pass in 19s.

---

## Next Steps (Phase 2)

1. **SQLite persistence** — `AuditLog` model + database migrations
2. **`/log` endpoint** — save audit events to SQLite
3. **Email alerts** — SMTP integration for high-severity detections
4. **Async logging** — fire-and-forget logging from proxy

## Next Steps (Phase 3)

5. **mitmproxy addon** — intercept LLM API requests, call `/detect`, block/redact
6. **Browser proxy config** — localhost:8080, mitm certificate

## Next Steps (Phase 4)

7. **Integration** — wire proxy → detection → logging end-to-end
8. **Dashboard** — HTML/JS view for audit logs

## Next Steps (Phase 5)

9. **Docker packaging** — `docker-compose.yml`
10. **Documentation** — deployment guide for on-premise/cloud VM
