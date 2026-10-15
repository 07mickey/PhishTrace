# PhishTrace Backend

Starter backend for **PhishTrace: Explainable Phishing URL Detection and Robustness Testing**.

## Current capabilities

- Flask app factory and modular API routes.
- `GET /api/health` health check.
- `POST /api/scan` URL validation and URL-structure feature extraction.
- Structured errors, request-size cap, logging configuration, and automated tests.
- Optional local SQLite storage that stores a SHA-256 fingerprint and extracted features, **not the raw submitted URL**. It is disabled by default.
- Optional Docker setup.

## Important limitation

The C++ DSA detection engine is **not connected yet**. The scan endpoint returns `assessment.label = "not_assessed"` and `detection_engine.integrated = false`. URL features are not a phishing verdict, and the absence of a suspicious feature does not mean a URL is safe. This backend never opens, fetches, or follows the submitted URL.

## Project structure

```text
PhishTrace_Backend/
├── .env.example
├── .gitignore
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── README.md
└── backend/
    ├── __init__.py
    ├── app.py
    ├── config.py
    ├── extensions.py
    ├── models/
    │   ├── __init__.py
    │   └── scan_result.py
    ├── routes/
    │   ├── __init__.py
    │   ├── health.py
    │   └── scan.py
    ├── schemas/
    │   ├── __init__.py
    │   └── scan_schema.py
    ├── services/
    │   ├── __init__.py
    │   ├── feature_extractor.py
    │   └── url_validator.py
    ├── utils/
    │   ├── __init__.py
    │   ├── error_handlers.py
    │   └── logger.py
    └── tests/
        ├── __init__.py
        ├── conftest.py
        ├── test_api.py
        └── test_url_validator.py
```

## Local setup (macOS)

Run from the project root, `PhishTrace_Backend`. First create a local `.env` with a freshly generated random key. The setup script refuses to overwrite an existing `.env`:

```bash
python3 scripts/setup_env.py
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m backend.app
```

The application loads `.env` using `python-dotenv`; real operating-system environment variables take precedence. `.env` is intentionally excluded from version control and must never be committed or included in shared ZIP files. For a production deployment, set `PHISHTRACE_ENV=production`, supply a unique high-entropy secret through the hosting platform's secret manager/environment, and keep debug mode disabled. The application refuses to start in production mode if the secret key is missing or too short.

The default local address is `http://127.0.0.1:5055`. Keep the server terminal open while testing.

### Test the API

In a second terminal:

```bash
curl -i http://127.0.0.1:5055/api/health

curl -i -X POST http://127.0.0.1:5055/api/scan \
  -H 'Content-Type: application/json' \
  -d '{"url":"example.com/login"}'
```

Expected health response is HTTP 200. The scan response should say `features_extracted`, while the assessment remains `not_assessed` until the detection engine has been integrated.

### Run automated tests

```bash
python -m pytest -q
```

Run the tests before merging or deploying. Report only the actual output; do not claim the full suite passes unless it has been run successfully in the environment being delivered.

### Optional scan-history storage

History storage is disabled by default to minimize retention of submitted URL information. If you deliberately enable it, set `PHISHTRACE_STORE_SCAN_HISTORY=true`. The local SQLite table stores the URL's SHA-256 fingerprint, timestamp, features, and `not_assessed` state; it does not store the raw URL. Do not enable this on a shared system without considering the privacy expectations of users.

Available settings:

- `PHISHTRACE_HOST` (default `127.0.0.1`; Docker uses `0.0.0.0` inside its container)
- `PHISHTRACE_PORT` (default `5055`)
- `PHISHTRACE_DEBUG` (default `false`)
- `PHISHTRACE_MAX_URL_LENGTH` (default `2048`)
- `PHISHTRACE_STORE_SCAN_HISTORY` (default `false`)
- `PHISHTRACE_DATABASE_PATH` (default `instance/phishtrace.sqlite3`)

` .env.example` documents settings only; it is not automatically loaded by Python. Set environment variables in the terminal or Docker environment when needed.

## Next integration steps

1. Agree on the C++ engine's JSON input/output contract with the DSA teammate.
2. Integrate the engine through a subprocess bridge with fixed executable paths, strict JSON parsing, and a timeout; never shell-concatenate a submitted URL.
3. Define the risk/category policy from actual algorithm evidence; do not represent heuristic features as calibrated probabilities.
4. Add evaluation and robustness endpoints backed by the team's actual labeled dataset and measured results.
5. Coordinate database schema and source/licensing details with the database teammate.


## Before production deployment

See [`docs/DEPLOYMENT_CHECKLIST.md`](docs/DEPLOYMENT_CHECKLIST.md) for secret handling, tests, database migration choices, production server setup, and privacy checks. Schema migrations are **not configured yet**: the optional scan-history table currently uses standard-library SQLite and `CREATE TABLE IF NOT EXISTS`. Before a production database needs schema evolution, select Alembic for the current plain-SQLite approach or move to SQLAlchemy + Flask-Migrate, then implement and verify initial and upgrade revisions.
