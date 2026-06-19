CIAI – LLM Data Leakage Prevention
===================================

Live Deployment
---------------

**LDOT Dashboard (Frontend):** https://ciai-llm-leakage-prevention.vercel.app

- [Home](https://ciai-llm-leakage-prevention.vercel.app) — Overview and quickstart
- [Sandbox Simulator](https://ciai-llm-leakage-prevention.vercel.app/simulator) — Test adversarial prompts in real time
- [Metrics & Audit Logs](https://ciai-llm-leakage-prevention.vercel.app/metrics) — Live security metrics
- [Governance](https://ciai-llm-leakage-prevention.vercel.app/governance) — Rate limits, hardening headers, alert routing

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

Docker-based testing note:

The container image now includes `curl`, which is required by the Docker Compose healthchecks used in local testing and CI.

For a Docker-first test run, start the API stack and run the test suite from inside the web container:

```bash
docker compose -f docker-compose.api.yml up -d
docker compose -f docker-compose.api.yml exec web alembic upgrade head
docker compose -f docker-compose.api.yml exec web pytest tests/test_detection.py -q
```

You can also run the same flow with the helper script or Makefile target:

```bash
bash scripts/docker_test.sh
make docker-test
```

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

Handoff for Enterprise Testing
------------------------------
Use these steps to deliver the project to an enterprise tester or ops team. Include source (git), runnable images (Docker), compose files, migrations, and the runbook.

1) What to include in the package
- `docker-compose.yml` and `docker-compose.override.yml`
- `.env.dev.example` and `HANDOFF_ENTERPRISE.md`
- `alembic/versions/` (migration scripts)
- `scripts/` (dev helpers and `oidc_test_provider.py`)
- `data/detect_benchmark.csv` (benchmark artifact if available)

2) How to push a release to Git (SSH)
Create a release branch, tag it, and push via SSH. Example commands:

```bash
# create a release branch and push
git checkout -b release/enterprise-ready
git add -A
git commit -m "Enterprise-ready release: handoff v1.0"
git push origin release/enterprise-ready

# create and push a signed tag
git tag -a v1.0-enterprise -m "Enterprise handoff v1.0"
git push origin v1.0-enterprise
```

If your git remote uses SSH (recommended for ops), ensure your SSH key is loaded (`ssh-agent` / `ssh-add`) and the remote URL uses the `git@` form (e.g. `git@github.com:org/repo.git`).

3) How to publish Docker images (recommended)
Build and push images to a registry the enterprise can pull from (GitHub Container Registry, ECR, GCR, or a private registry). Example using GHCR or a private registry:

```bash
# build
docker build -t my-registry.example.com/ciai-api:web:1.0 .

# tag & push
docker tag ciai-api:web:1.0 my-registry.example.com/ciai-api:web:1.0
docker push my-registry.example.com/ciai-api:web:1.0

# export tarball (if they cannot pull images)
docker save my-registry.example.com/ciai-api:web:1.0 -o ciai-api_web_1.0.tar
```

4) Quick tester checklist
- Confirm `alembic upgrade head` runs successfully against staging DB.
- Start stack: `docker compose up -d` or `bash scripts/dev_setup.sh` for local dev.
- Verify RBAC with tokens (use `scripts/oidc_test_provider.py` or enterprise IdP).
- Run detection benchmark: `pytest tests/test_detection_benchmark.py -q` and check `data/detect_benchmark.csv`.

5) Security notes
- Never include production secrets in the package. Share Vault/KMS credentials out-of-band.
- For `SECRETS_MODE=managed_required`, provide Vault or KMS credentials to the testers, or set `SECRETS_MODE=optional` for initial evaluation.

6) Contact & walkthrough
Include a 30–60 minute walkthrough window and a contact for troubleshooting. Attach `HANDOFF_ENTERPRISE.md` for detailed run steps.

