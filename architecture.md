# Architecture – Lean MVP

## High‑Level Diagram
┌─────────────────────────────────────────────────────────────┐
│ EMPLOYEE │
│ (Browser / IDE / API call) │
└───────────────────────────────┬─────────────────────────────┘
│
▼
┌─────────────────────────────────────────────────────────────┐
│ PROXY / EXTENSION │
│ - Intercepts request to LLM endpoint │
│ - Sends prompt to detection engine │
│ - Blocks/redacts if sensitive data found │
└───────────────────────────────┬─────────────────────────────┘
│
▼
┌─────────────────────────────────────────────────────────────┐
│ DETECTION & REDACTION │
│ - Regex rules (Aadhaar, PAN, credit card, API keys) │
│ - Presidio for NER (names, locations, etc.) │
│ - Returns clean prompt or BLOCK response │
└───────────────────────────────┬─────────────────────────────┘
│
▼
┌─────────────────────────────────────────────────────────────┐
│ LOGGING & ALERTS │
│ - Store redacted prompt, timestamp, user ID, decision │
│ - Send email/slack alert on detection │
│ - Simple dashboard for audit logs │
└─────────────────────────────────────────────────────────────┘



## Data Flow
1. Employee sends prompt to LLM (via corporate ChatGPT, Copilot, or custom app).
2. Proxy intercepts the HTTP request.
3. Detection engine scans prompt for sensitive patterns.
4. If found → redact or block; log the event; send alert.
5. If clean → forward to LLM; log metadata (no content).
6. LLM response is also scanned before returning to user (optional).

## Security & Privacy
- **No raw PII stored** – logs keep only redacted/ hashed versions.
- **Encryption** – TLS between proxy and central service.
- **Authentication** – API keys for proxy‑to‑service calls (simple shared secret).

## Scalability Notes (for MVP)
- Single‑instance deployment is fine for up to 500 employees.
- For larger scale, use PostgreSQL instead of SQLite, and deploy behind a load balancer.



