#!/usr/bin/env bash
set -euo pipefail

# Pull images (if image names are set) and start the stack using images compose override
ROOT_DIR=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT_DIR"

echo "Ensure .env exists (copy .env.dev.example and edit if needed)"
if [ ! -f .env ]; then
  cp .env.dev.example .env
  echo "Created .env from .env.dev.example - please edit with staging values if needed"
fi

echo "Pulling images..."
if [ -n "${IMAGE_WEB:-}" ]; then
  docker pull "${IMAGE_WEB}"
fi
if [ -n "${IMAGE_WORKER:-}" ]; then
  docker pull "${IMAGE_WORKER}"
fi

echo "Starting DB and Redis"
docker compose up -d db redis

echo "Running migrations"
docker compose run --rm migrate

echo "Starting web and worker from images"
docker compose -f docker-compose.yml -f docker-compose.images.yml up -d

echo "Stack started. Tail logs with: docker compose logs -f web"
