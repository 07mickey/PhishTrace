# PhishTrace pre-deployment checklist

## Secrets and configuration

- Run `python scripts/setup_env.py` on the target machine to create a private `.env` file with a new random `PHISHTRACE_SECRET_KEY`.
- `.env` is ignored by Git. Never commit it, put its contents in the ZIP, or share the key in chat or screenshots.
- Before a production run, set `PHISHTRACE_ENV=production`, use a unique production key, and keep debug mode disabled.
- Prefer the hosting provider's secret manager/environment variables over a `.env` file for managed production deployments.
- The app loads `.env` using `python-dotenv`; real environment variables take precedence over values in `.env`.

## Automated tests

From the project root with the project virtual environment activated:

```bash
python -m pip install -r requirements.txt
python -m pytest -q
```

Do not deploy if tests fail. Record the actual test result in the project README or release notes; do not report a test suite as passing unless it was run successfully.

## Database migrations

The current starter stores optional scan history using Python's built-in `sqlite3` and creates one table with `CREATE TABLE IF NOT EXISTS`. It does not yet use SQLAlchemy models, and the database is optional/disabled by default. Do not claim automated schema migrations are configured.

Before a production deployment that needs evolving schema, choose one migration strategy and implement it consistently:

- **Alembic directly** if retaining plain `sqlite3` and writing explicit schema migrations; or
- **SQLAlchemy + Flask-Migrate** if moving the database layer to SQLAlchemy models.

Then add an initial revision, verify an upgrade from an empty database, verify an upgrade from the previous schema, and document backups/rollback. Avoid scaffolding migrations before the database strategy is chosen because it can create two competing schema-management paths.

## Other production checks

- Use a production WSGI server rather than Flask's development server.
- Set the allowed host/bind address according to the deployment platform; do not expose the local development service unintentionally.
- Keep request size limits and structured errors enabled.
- Do not fetch, open, or follow user-submitted URLs.
- Decide privacy/retention rules before enabling scan-history storage.
- Integrate and test the real DSA engine before presenting a phishing assessment. Until then, the API correctly returns `not_assessed`.
