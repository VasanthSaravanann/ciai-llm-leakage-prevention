# CIAI – Lean MVP for LLM Data Leakage Prevention

## What is this?
A lightweight, resource‑efficient solution to monitor, detect, and prevent sensitive data leakage (PII, secrets) from employee interactions with LLMs (ChatGPT, Copilot, internal models). Built for Indian enterprises that need DPDP Act compliance.

## Core Components
- **Proxy / Browser Extension** – captures prompts and LLM responses.
- **Detection Engine** – regex + Microsoft Presidio for PII/PCI/secret detection.
- **Logging & Alerting** – stores redacted logs, sends email alerts.
- **Redaction / Blocking** – removes or blocks sensitive data before it reaches the LLM.

## Tech Stack (Minimal, Open‑Source)
- Python 3.10+
- FastAPI (for the central logging/control service)
- mitmproxy or a simple Chrome extension (choose one)
- Presidio (Microsoft) – for PII detection
- SQLite (development) / PostgreSQL (production)
- SMTP (email alerts)

## Quick Start
1. Clone this repo.
2. Run `docker-compose up` (see `docker-compose.yml`).
3. Configure your browser to use the proxy (or install the extension).
4. Access the dashboard at `http://localhost:8080`.

## Project Structure
.
├── README.md
├── ARCHITECTURE.md
├── IMPLEMENTATION_PLAN.md
├── BUILD_PROXY.md
├── BUILD_DETECTION.md
├── BUILD_LOGGING_ALERTS.md
├── BUILD_REDACTION.md
├── INTEGRATION_GUIDE.md
├── docker-compose.yml
└── src/
├── proxy/ # mitmproxy addon or extension code
├── detection/ # detection engine
├── logging/ # database models & audit
├── redaction/ # redaction/blocking logic
├── api/ # FastAPI control plane
└── dashboard/ # simple HTML/JS dashboard (optional)



