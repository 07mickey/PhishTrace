"""Small standard-library SQLite extension; history is opt-in."""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from flask import current_app, g


def init_app(app) -> None:
    """Prepare an optional database and close request-scoped connections."""
    app.teardown_appcontext(close_db)
    if app.config.get("STORE_SCAN_HISTORY", False):
        init_db(app.config["DATABASE_PATH"])


def init_db(database_path: str) -> None:
    path = Path(database_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(path), timeout=5)
    try:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url_sha256 TEXT NOT NULL,
                created_at TEXT NOT NULL,
                features_json TEXT NOT NULL,
                assessment TEXT NOT NULL
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS ix_scan_results_created_at "
            "ON scan_results (created_at)"
        )
        connection.commit()
    finally:
        connection.close()


def get_db() -> sqlite3.Connection:
    if "phishtrace_db" not in g:
        database_path = current_app.config["DATABASE_PATH"]
        Path(database_path).parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(database_path, timeout=5)
        connection.row_factory = sqlite3.Row
        g.phishtrace_db = connection
    return g.phishtrace_db


def close_db(_error: BaseException | None = None) -> None:
    connection = g.pop("phishtrace_db", None)
    if connection is not None:
        connection.close()


def save_scan_result(result: Any) -> None:
    """Persist only a URL fingerprint and features; never retain the raw URL."""
    connection = get_db()
    connection.execute(
        """INSERT INTO scan_results
           (url_sha256, created_at, features_json, assessment)
           VALUES (?, ?, ?, ?)""",
        (
            result.url_sha256,
            result.created_at,
            json.dumps(result.features, sort_keys=True),
            result.assessment,
        ),
    )
    connection.commit()
