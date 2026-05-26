Enterprise Handoff Runbook
=========================

Quick steps to run the project in a staging environment suitable for enterprise testing.

1) Prerequisites
  - Docker & Docker Compose
  - Python 3.11 for local scripts (optional)

2) Start local services for staging

Copy the dev env and start services:

```bash
cp .env.dev.example .env
bash scripts/dev_setup.sh
```

3) Optional: start the local OIDC test provider (useful for RBAC flows)

```bash
bash scripts/run_oidc.sh &
# OIDC provider will listen on port 9000 by default
```

Set the following env vars for the app to use the test provider:

```
OIDC_ENABLED=1
OIDC_ISSUER=http://localhost:9000
OIDC_AUDIENCE=ciai
OIDC_JWKS_URL=http://localhost:9000/.well-known/jwks.json
```

4) Run Alembic migrations

```bash
docker compose run --rm migrate
```

5) Run the detection benchmark (produces `data/detect_benchmark.csv`)

```bash
pytest tests/test_detection_benchmark.py -q
```

6) Notes for enterprise testers
  - `GATEWAY_MODE=fail_closed` is recommended for security testing.
  - To test managed secrets flows, configure a Vault or AWS KMS and set `SECRETS_MODE=managed_required`.
  - The CI job `enterprise-ci` runs the benchmark matrix and uploads the CSV artifact.
