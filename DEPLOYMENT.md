# Deployment Notes

## Staging prerequisites
- Postgres and Redis must be available via Docker Compose or managed services.
- Populate `.env` from `.env.example`.
- Set a real staging `LLM_API_KEY` and `LLM_PROVIDER` (for example `openai`).
- Set `ENCRYPT_LOGS=1` so the audit trace stores encrypted payload metadata.

## Staging flow
1. Copy `.env.example` to `.env` and update secrets.
2. Start services with Docker Compose or your cloud runtime.
3. Run `alembic upgrade head`.
4. Verify encryption with `python scripts/verify_encryption.py`.
5. Run `python scripts/harness.py`.
6. Run `python scripts/load_test.py`.

## Current limitations
- Cloud provisioning (RDS/ElastiCache/KMS/EKS or ECS/Fargate) is still external to the repo.
- The repo has the code paths and scripts needed for real-LLM staging, but the runtime environment must be supplied.
