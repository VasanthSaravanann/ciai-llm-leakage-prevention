CIAI – LLM Data Leakage Prevention
===================================

Overview
--------
Lightweight project to detect and prevent sensitive data (PII, secrets, India-specific IDs) from leaking into LLM prompts. This repository contains:

- Detection engine (regex + Microsoft Presidio)
- FastAPI control plane (`/detect`, `/log`, `/health`)
- Audit logging and optional envelope encryption
- Staging scripts, Alembic migrations, and CI scaffolding

Goal
----
Make it easy for trainers and reviewers to run the full detect → log → LLM flow locally (mock or real provider) and in a staging environment.

Contents
--------
- `src/` — application code (API, detection, logging, llm adapters)
- `scripts/` — helper scripts: `harness.py`, `verify_encryption.py`, `run_staging.sh`
- `alembic/` — migration scripts
- `docker-compose.yml` — local staging stack (Postgres + Redis + web + worker)
- `tests/` — unit tests and security audit

Quick roadmap for a tester
--------------------------
1. Local smoke test (fast, no external services): uses `sqlite` and the mock LLM provider.
2. Staging test (recommended for real-LLM): Postgres + Redis + OpenAI (or managed LLM).
3. Production-like test: provision managed DB, Redis, and KMS; run CI / red-team suites.

Precise step-by-step (local smoke test)
--------------------------------------
1. Create and activate a venv, install deps, and download the spaCy model:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m spacy download en_core_web_sm
```

2. Set environment variables for a local smoke test (mock LLM):

```bash
export PYTHONPATH=$PWD
export DATABASE_URL=sqlite:///./dev.db
export REDIS_URL=redis://localhost:6379/0   # optional
export API_KEYS=testkey
export JWT_SECRET_KEY=devsecret
export LLM_PROVIDER=mock
export LLM_API_KEY=    # leave blank for mock
export ENCRYPT_LOGS=0
```

3. Start the API (venv executables recommended):

```bash
.venv/bin/uvicorn src.api.main:app --reload --port 8000
```

4. Quick checks:

```bash
# health
curl http://localhost:8000/health

# example detection (no API key header required for local tests by default)
curl -X POST http://localhost:8000/detect -H "Content-Type: application/json" -d '{"text":"My PAN is ABCDE1234F"}'
```

5. Run unit tests (run only the `tests/` package):

```bash
.venv/bin/pytest tests -q
```

6. Run the harness (mock LLM) to exercise the end-to-end flow:

```bash
.venv/bin/python scripts/harness.py
```

Staging flow (real LLM testing)
--------------------------------
Use this when you have Docker locally or managed Postgres/Redis and an LLM key.

1. Prepare secrets (example env):

```bash
export DATABASE_URL=postgresql+psycopg2://user:pass@host:5432/ciai_audit
export REDIS_URL=redis://host:6379/0
export API_KEYS=staging-key-1
export JWT_SECRET_KEY=strong-secret
export LLM_PROVIDER=openai
export LLM_API_KEY=sk-...
export ENCRYPT_LOGS=1
# If using AWS KMS:
export AWS_REGION=us-east-1
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export KMS_KEY_ID=arn:aws:kms:...
```

2. Install deps and run Alembic migrations:

```bash
.venv/bin/pip install -r requirements.txt
.venv/bin/alembic upgrade head
```

3. Start services:

If using Docker Compose (local staging):

```bash
docker compose up -d
docker compose exec web alembic upgrade head
```

Or run the API directly as above if pointing at managed Postgres/Redis.

4. Verify encryption (if enabled) and run harness to send real LLM traffic:

```bash
.venv/bin/python scripts/verify_encryption.py
.venv/bin/python scripts/harness.py
```

Notes about local LLMs
---------------------
- `src/llm/adapter.py` currently supports `mock` (httpbin) and `openai` provider calls.
- To test a local LLM server that implements an OpenAI-compatible REST API, either:
  - Run a small proxy that forwards OpenAI-compatible requests to your local model and set `LLM_PROVIDER=openai` and `LLM_API_KEY` accordingly, or
  - Modify `src/llm/adapter.py` to point the OpenAI request URL to your local server (set a new `OPENAI_BASE_URL` env var and update the adapter to use it).

Environment variables (summary)
--------------------------------
- `DATABASE_URL` — SQLAlchemy URL (sqlite for quick tests or Postgres for staging)
- `REDIS_URL` — Redis URL for rate-limiter and Celery broker
- `API_KEYS` — comma-separated API keys permitted to call the API
- `JWT_SECRET_KEY` — secret for JWT bearer support
- `LLM_PROVIDER` — `mock` or `openai` (default `mock`)
- `LLM_API_KEY` — provider API key (OpenAI key when `openai`)
- `ENCRYPT_LOGS` — `0` or `1` to enable storing ciphertext metadata (requires KMS or Fernet fallback)
- `KMS_KEY_ID`, `AWS_*` — optional for envelope encryption via AWS KMS

Troubleshooting
---------------
- If `alembic` is not found, run it from the venv: `.venv/bin/alembic upgrade head`.
- If tests fail with `ModuleNotFoundError: No module named 'src'`, ensure `PYTHONPATH=$PWD` is exported or run tests with the venv from repo root.
- If you cannot run Docker locally, use managed Postgres/Redis and run the API directly.

Where to look next
------------------
- Read `TESTING.md` for the 45-point security audit details.
- Use `scripts/run_staging.sh` to automate a local staging run (it calls compose and runs migrations where appropriate).
- Use `DEPLOYMENT.md` for deployment guidance and secrets checklist.

Contact / Maintainers
---------------------
The repo owner and contributors are listed in the Git history; open issues or pull requests for changes to the adapter or runbook.

License / Notes
---------------
This repo is a demo/hardening exercise — review the code and dependencies before running with production data or real customer traffic.
