#!/usr/bin/env bash
set -euo pipefail

# Dev setup: start db and redis, run migrations, and start app services.
ROOT_DIR=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT_DIR"

echo "Bringing up db and redis..."
docker compose up -d db redis

echo "Waiting for DB to be ready..."
until docker compose exec -T db pg_isready -U postgres -d caiai_audit >/dev/null 2>&1; do
  sleep 1
done

echo "Running alembic migrations..."
docker compose run --rm migrate

echo "Bringing up web, worker, and beat..."
docker compose up -d web worker beat

echo "All services started. Tail logs with: docker compose logs -f web"
