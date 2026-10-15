from pathlib import Path
import pytest

from backend.app import create_app


@pytest.fixture()
def app(tmp_path: Path):
    test_app = create_app({
        "TESTING": True,
        "DEBUG": False,
        "STORE_SCAN_HISTORY": False,
        "DATABASE_PATH": str(tmp_path / "test.sqlite3"),
        "MAX_URL_LENGTH": 2048,
        "MAX_CONTENT_LENGTH": 16 * 1024,
    })
    yield test_app


@pytest.fixture()
def client(app):
    return app.test_client()
