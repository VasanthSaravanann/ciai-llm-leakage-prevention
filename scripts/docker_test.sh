#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.api.yml}"
TEST_TARGET="${TEST_TARGET:-tests/test_detection.py -q}"

compose() {
  docker compose -f "$COMPOSE_FILE" "$@"
}

cleanup() {
  if [[ "${KEEP_STACK:-0}" != "1" ]]; then
    compose down -v >/dev/null 2>&1 || true
  fi
}

trap cleanup EXIT

echo "Using compose file: $COMPOSE_FILE"
echo "Starting API stack..."
compose up -d --build

echo "Running migrations..."
compose exec web alembic upgrade head

echo "Running tests: $TEST_TARGET"
compose exec web bash -lc "pytest $TEST_TARGET"

echo "Docker test flow completed successfully."