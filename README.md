# CIAI – LLM Data Leakage Prevention

> Lightweight, resource-efficient solution to monitor, detect, and prevent sensitive data (PII, secrets, India-specific IDs) from leaking into LLM prompts. Built for Indian enterprises needing DPDP Act compliance.

## Status

| Phase | Component | Status |
|-------|-----------|--------|
| **Phase 1** | Detection Engine + FastAPI API + Tests | ✅ Complete |
| Phase 2 | SQLite Logging + Email Alerts | Planned |
| Phase 3 | mitmproxy Interceptor | Planned |
| Phase 4 | Integration + Dashboard | Planned |
| Phase 5 | Docker Packaging + Docs | Planned |

## What It Detects

### India-Specific (Regex + Luhn)
| Pattern | Example | Action |
|---------|---------|--------|
| **Aadhaar** (12-digit, 4-4-4) | `2345 6789 0123` | Block + Redact |
| **PAN** (5L-4D-1L) | `ABCDE1234F` | Block + Redact |
| **Credit Card** (13-19 digit + Luhn) | `4111 1111 1111 1111` | Block + Redact |

### API Keys & Secrets
| Pattern | Example | Action |
|---------|---------|--------|
| OpenAI Key | `sk-abc...` | Block + Redact |
| Anthropic Key | `sk-ant-api03-...` | Block + Redact |
| AWS Access Key | `AKIAIOSFODNN7EXAMPLE` | Block + Redact |
| AWS Secret | `aws_secret_access_key = ...` | Block + Redact |
| Generic API Key | `api_key = ...` | Block + Redact |
| Bearer Token | `Bearer eyJhbG...` | Block + Redact |
| Password/Secret | `password = ...` | Block + Redact |

### PII (Microsoft Presidio NER)
Email, phone, person name, location, IP address, URL, date/time, credit card

## Tech Stack

- **Python 3.10+**
- **FastAPI** — API control plane
- **Presidio** (Microsoft) — PII detection + redaction
- **spaCy** (`en_core_web_sm`, 13MB) — NLP engine
- **SQLite** — audit log storage (Phase 2)
- **mitmproxy** — HTTP interceptor (Phase 3)
- **SMTP** — email alerts (Phase 2)

## Quick Start

### Prerequisites
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m spacy download en_core_web_sm
```

### Run the API
```bash
uvicorn src.api.main:app --reload --port 8000
```

### Test It
```bash
# Health check
curl http://localhost:8000/health

# Clean text (should pass)
curl -X POST http://localhost:8000/detect \
  -H "Content-Type: application/json" \
  -d '{"text": "Hello world, how are you?"}'

# PAN detection (should block)
curl -X POST http://localhost:8000/detect \
  -H "Content-Type: application/json" \
  -d '{"text": "My PAN is ABCDE1234F"}'

# Aadhaar detection (should block)
curl -X POST http://localhost:8000/detect \
  -H "Content-Type: application/json" \
  -d '{"text": "My Aadhaar is 234567890123"}'
```

### Run Tests
```bash
pytest tests/test_detection.py -v
```

**34/34 tests passing** — covers Luhn, Aadhaar, PAN, credit cards, API keys, severity, redaction, and API endpoints.

## Project Structure

```
.
├── .gitignore
├── BUILD-LOG-PHASE1.md
├── README.md
├── requirements.txt
├── src/
│   ├── __init__.py
│   ├── api/
│   │   ├── __init__.py
│   │   └── main.py              # FastAPI: /detect, /log, /health
│   ├── detection/
│   │   ├── __init__.py
│   │   └── detect.py            # Core engine: regex + Presidio
│   ├── logging/                 # Phase 2: SQLite models + audit
│   └── proxy/                   # Phase 3: mitmproxy addon
├── tests/
│   ├── __init__.py
│   └── test_detection.py        # 34 unit tests
└── docs/                        # Original design docs (preserved)
    ├── architecture.md
    ├── implementation plan.md
    ├── addon.md
    ├── Chrome extension.md
    ├── emailalert.md
    └── loggingendpoint.md
```

## Architecture

```
┌──────────────┐
│  EMPLOYEE    │
│  (Browser)   │
└──────┬───────┘
       │ prompt
       ▼
┌──────────────────────┐
│  PROXY / EXTENSION   │  ← Phase 3 (mitmproxy)
│  intercepts request  │
└──────┬───────────────┘
       │ text
       ▼
┌──────────────────────┐
│  DETECTION ENGINE    │  ← Phase 1 ✅
│  regex + Presidio    │
│  → block / redact    │
└──────┬───────────────┘
       │ event
       ▼
┌──────────────────────┐
│  LOGGING + ALERTS    │  ← Phase 2 (SQLite + SMTP)
│  store + notify      │
└──────────────────────┘
```

## API Reference

### `POST /detect`
Analyze text for sensitive data.

**Request:**
```json
{ "text": "My PAN is ABCDE1234F" }
```

**Response:**
```json
{
  "detections": ["PAN"],
  "block": true,
  "redact": true,
  "redacted_text": "My PAN is [REDACTED]",
  "severity": "high"
}
```

### `POST /log`
Store audit event (Phase 2 placeholder).

### `GET /health`
Health check.

## Severity Classification

| Level | Condition | Action |
|-------|-----------|--------|
| **high** | Aadhaar, PAN, credit card, API key, secret | Block request |
| **medium** | 2+ Presidio detections (email + phone, etc.) | Redact |
| **low** | Single Presidio detection | Redact |
| **none** | Clean text | Pass through |

## Build Log

Detailed build log with design decisions, issues, and verification:
→ [`BUILD-LOG-PHASE1.md`](BUILD-LOG-PHASE1.md)
