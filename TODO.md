# Deployment TODO: LLM Productionization

This file lists the remaining tasks to move the project to a safe, production-capable LLM deployment.

- [ ] Provision staging infra (managed Postgres, Redis, KMS) and set secrets (API_KEYS, DATABASE_URL, REDIS_URL, LLM_API_KEY, KMS_KEY_ID, JWT_SECRET_KEY)
- [ ] Run Alembic migrations and start staging (docker-compose or cloud)
- [ ] Run harness end-to-end against staging (mock LLM or real with staging LLM key and strict quotas)
- [ ] Integrate `src/logging/encryption.py` KMS envelope encryption into DB write path (encrypt redacted payloads)
- [ ] Complete provider-specific LLM adapters (OpenAI, Anthropic) and credential handling + provider tests
- [ ] Implement Redis-backed rate-limiter and per-client quota enforcement
- [ ] Add periodic retention/cleanup Celery task for DB (retention policy enforcement)
- [ ] Implement retriever + vector DB (embeddings pipeline + vector store)
- [ ] Add JWT issuance service / client registration + scopes and client onboarding flow
- [ ] Add CI/CD deployment pipeline to staging (Terraform/Helm + GitHub Actions secrets) and test deploy
- [ ] Add observability dashboards & alerting (Prometheus + Grafana + alert rules)
- [ ] Run security review & penetration test of staging flow (external vendor or in-house pen-test)
- [x] Create and push this TODO file to the repository

Notes
- For any real-LLM tests, use a dedicated staging LLM key with strict usage quotas and avoid sending PII until encryption is verified.
- Consider enabling KMS envelope encryption and rotating keys before storing redacted payloads.
