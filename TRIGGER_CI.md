Triggering the API CI workflow

To execute the remaining verification steps (build image, start stack, run migrations, smoke tests) run the following from the repo root.

1) Commit this file and push to `main` (or `develop`) to trigger the workflow on GitHub Actions:

```bash
git add TRIGGER_CI.md
git commit -m "chore(ci): trigger API CI workflow"
git push origin main
```

2) Or trigger manually using GitHub CLI (authenticated):

```bash
gh workflow run api-ci.yml --ref main
```

3) To run locally (requires Docker & gh):

```bash
# build image
make build

# start stack
make up

# run migrations
make migrate

# run smoke tests
make smoke

# teardown
make down
```

After you push or trigger the workflow, share the Actions run URL or the logs and I'll analyze failures and finish the remaining todos.