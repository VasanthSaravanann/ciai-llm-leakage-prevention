Staging Setup

1. Provision Postgres (managed DB) and set `DATABASE_URL` in environment, e.g:

   postgresql+psycopg2://user:password@hostname:5432/ciai_audit

2. Create or configure AWS KMS key and set `KMS_KEY_ID` in environment for envelope encryption if desired.

3. Set `API_KEY` and other secrets in the environment or in CI secrets.

4. Install dependencies and run migrations (using Alembic when configured):

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-dev.txt
python -m spacy download en_core_web_sm
# Create DB schema (if not using alembic yet)
python -c "from src.logging.database import Base, engine; Base.metadata.create_all(bind=engine)"
```

5. Start the app locally for staging:

```bash
uvicorn src.api.main:app --host 0.0.0.0 --port 8000
```

6. Test a detection:

```bash
curl -X POST http://localhost:8000/detect -H 'X-API-KEY: $API_KEY' -H 'Content-Type: application/json' -d '{"text":"My secret is sk-AAAA..."}'
```

Notes:
- For production, use Alembic for schema migrations and rotate API keys via a secrets manager.
- For real LLM traffic testing, run a small send->/detect->LLM harness and ensure `block:false` before forwarding requests.

7. Alembic migrations (when using Postgres)

```bash
# install alembic in your venv
pip install alembic
export DATABASE_URL=postgresql+psycopg2://user:password@hostname:5432/ciai_audit
alembic upgrade head
```

8. GitHub Actions secrets

Add the following repository secrets in GitHub:
- `API_KEY` — service API key for the detector
- `DATABASE_URL` — Postgres connection string for staging
- `LLM_API_KEY` — staging LLM provider key
- `KMS_KEY_ID` — optional KMS key for envelope encryption

