"""Environment-based configuration for PhishTrace."""
from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env", override=False)


def _as_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _as_int(value: str | None, default: int) -> int:
    if value is None:
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


class Config:
    """Default app settings. Override values in create_app for tests."""

    ENV = os.getenv("PHISHTRACE_ENV", "development").strip().lower()
    DEBUG = _as_bool(os.getenv("PHISHTRACE_DEBUG"), False)
    SECRET_KEY = os.getenv("PHISHTRACE_SECRET_KEY")
    if ENV == "production":
        if not SECRET_KEY or len(SECRET_KEY) < 32:
            raise RuntimeError(
                "PHISHTRACE_SECRET_KEY must be set to a high-entropy value of at least 32 characters in production."
            )
        if DEBUG:
            raise RuntimeError("DEBUG mode must be disabled in production.")
    if not SECRET_KEY:
        SECRET_KEY = "local-development-only-not-for-production"

    MAX_CONTENT_LENGTH = 16 * 1024
    MAX_URL_LENGTH = _as_int(os.getenv("PHISHTRACE_MAX_URL_LENGTH"), 2048)
    HOST = os.getenv("PHISHTRACE_HOST", "127.0.0.1")
    PORT = _as_int(os.getenv("PHISHTRACE_PORT"), 5055)
    STORE_SCAN_HISTORY = _as_bool(os.getenv("PHISHTRACE_STORE_SCAN_HISTORY"), False)
    DATABASE_PATH = os.getenv(
        "PHISHTRACE_DATABASE_PATH",
        str(PROJECT_ROOT / "instance" / "phishtrace.sqlite3"),
    )
    JSON_SORT_KEYS = False
