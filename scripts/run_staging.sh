#!/usr/bin/env bash
set -euo pipefail

# Run full staging flow locally: bring up compose, run migrations, verify encryption, run harness and load test.
# Requires Docker + docker compose installed and a virtualenv at .venv with deps installed.

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

if ! command -v docker >/dev/null 2>&1; then
  echo "ERROR: docker not found in PATH. Install Docker Desktop and ensure 'docker' is available." >&2
  exit 2
fi

if ! docker compose version >/dev/null 2>&1; then
  echo "ERROR: docker compose not available. Use Docker Desktop with Compose V2 or install docker-compose." >&2
  exit 2
fi

if [ -f .env ]; then
  echo "Loading environment from .env"
  set -a
  source .env
  set +a
fi

echo "Starting docker compose..."
docker compose up -d

echo "Waiting for Postgres to be ready..."
for i in {1..30}; do
  if docker exec $(docker ps --filter name=db -q) pg_isready -U postgres >/dev/null 2>&1; then
    echo "Postgres ready"
    break
  fi
  sleep 2
done

echo "Activating venv and running migrations"
if [ -f .venv/bin/activate ]; then
  # shellcheck source=/dev/null
  source .venv/bin/activate
else
  echo "Warning: virtualenv .venv not found. Running alembic with system Python." >&2
fi

alembic upgrade head

echo "Verifying encryption (ENCRYPT_LOGS=${ENCRYPT_LOGS:-0})"
python scripts/verify_encryption.py || true

echo "Running harness"
python scripts/harness.py || true

echo "Running load test (short)"
python scripts/load_test.py --requests 50 --concurrency 5 || true

echo "Staging run complete. Check logs and the dashboard at http://localhost:8000"
