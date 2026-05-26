PY?=python

.PHONY: help build up migrate smoke down

help:
	@echo "Available targets:"
	@echo "  make build    - Build Docker image"
	@echo "  make up       - Start stack via docker-compose"
	@echo "  make migrate  - Run alembic upgrade head inside web"
	@echo "  make smoke    - Run smoke tests"
	@echo "  make down     - Stop stack"

build:
	docker build -t ciai-api:latest .

up:
	docker compose -f docker-compose.api.yml up -d

migrate:
	# Run migrations inside the running web container
	docker compose -f docker-compose.api.yml exec web alembic upgrade head

smoke:
	bash scripts/smoke_test.sh

down:
	docker compose -f docker-compose.api.yml down -v

ci:
	# Trigger CI workflow locally using GitHub CLI (requires `gh` & authenticated)
	gh workflow run api-ci.yml --ref main

