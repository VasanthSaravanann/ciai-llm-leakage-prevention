# Implementation Plan – 6 Weeks to MVP

## Week 1: Setup & Proxy
- Set up Python environment, FastAPI skeleton.
- Choose proxy method: **mitmproxy** (easiest) or build a Chrome extension.
- Write mitmproxy addon to capture `https://api.openai.com/v1/chat/completions` and forward to local API.

## Week 2: Detection Engine
- Implement regex patterns for:
  - Aadhaar (4‑4‑4 digits)
  - PAN (5 letters + 4 digits + letter)
  - Credit card numbers (Luhn check)
  - API keys (generic `sk-...`, `Bearer ...`)
- Integrate Presidio for names, emails, phone numbers.
- Create a simple Python function `detect_sensitive(text)` returning list of detected types.

## Week 3: Logging & Alerting
- Set up SQLite database with table `audit_log` (id, timestamp, user_id, redacted_prompt, detection_types, action_taken, llm_response_redacted).
- Write API endpoints: `/detect` (POST) returns detection result; `/log` (POST) stores event.
- Configure SMTP (Gmail or SendGrid) to send alert emails when high‑severity detection occurs.

## Week 4: Redaction & Blocking
- Implement redaction: replace detected text with `[REDACTED]`.
- Implement blocking: return a custom JSON error (`{"error": "Request blocked due to sensitive data"}`) without forwarding to LLM.
- Make redaction/blocking configurable per customer.

## Week 5: Integration & Dashboard
- Connect proxy addon to the FastAPI endpoints.
- Build a minimal dashboard (Flask or FastAPI + simple HTML tables) to view audit logs.
- Add basic authentication (username/password) for dashboard access.

## Week 6: Pilot Deployment & Documentation
- Package everything into Docker containers (see `docker-compose.yml`).
- Write deployment instructions for on‑premise or cloud VM.
- Onboard 2‑3 pilot customers (free 30‑day trial).
- Collect feedback and iterate.
