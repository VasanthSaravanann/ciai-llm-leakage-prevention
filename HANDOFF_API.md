# CIAI API Handoff Guide

## Overview
This document provides enterprise-ready instructions for deploying and testing the CIAI LLM leakage prevention API.

## Quick Start

### Prerequisites
- Docker & Docker Compose
- Python 3.11+
- Git

### Deployment Steps

#### 1. Clone & Setup Environment
```bash
git clone <repo>
cd ciai-llm-leakage-prevention
cp .env.enterprise.example .env
```

#### 2. Configure Environment
Edit `.env` with your settings: database credentials, Redis connection, JWT/OIDC settings, API keys, email/alerts, and KMS/encryption keys.

#### 3. Start Services
```bash
docker-compose -f docker-compose.api.yml up -d
```

#### 4. Run Migrations
```bash
docker-compose -f docker-compose.api.yml exec web alembic upgrade head
```

#### 5. Verify Deployment
```bash
bash scripts/smoke_test.sh
```

## API Endpoints

All endpoints accept `X-API-KEY` header or a Bearer JWT (if configured).

- `POST /detect` – Analyze text for sensitive data
- `GET /health` – Health check (admin guarded)
- `POST /log` – Store audit events
- `GET /metrics` – Prometheus metrics (admin only)
- `GET /dashboard` – Audit log viewer (admin only)

## Testing

### Local Testing
```bash
docker-compose -f docker-compose.api.yml up
pytest tests/
bash scripts/smoke_test.sh
```

### CI/CD
See `.github/workflows/api-ci.yml` for example workflow that builds the image, runs unit tests, and executes smoke tests.

## Monitoring

Health check and metrics examples:

```bash
curl -H "X-API-KEY: $API_KEY" http://localhost:8000/health
curl -H "X-API-KEY: $API_KEY" http://localhost:8000/metrics
```

## Security Checklist

- API key configured and rotated
- Database credentials strong
- CORS/CSP configured
- Rate limits enabled
- TLS configured in production
- Audit logging enabled
- Redis password set

## Troubleshooting

If services fail to start, check `.env`, Docker daemon, and port conflicts. For detection issues, ensure spaCy models are installed: `python -m spacy download en_core_web_sm`.

## Version Info

- API Version: 1.0.0
- Last Updated: 2026-05-26
