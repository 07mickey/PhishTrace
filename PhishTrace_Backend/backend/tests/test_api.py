def test_health_endpoint(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.get_json() == {"service": "PhishTrace API", "status": "ok"}


def test_scan_extracts_features_but_does_not_claim_verdict(client):
    response = client.post("/api/scan", json={"url": "example.com/login?next=%2Fhome"})
    body = response.get_json()
    assert response.status_code == 200
    assert body["status"] == "features_extracted"
    assert body["url"] == "https://example.com/login?next=%2Fhome"
    assert body["assessment"]["label"] == "not_assessed"
    assert body["detection_engine"]["integrated"] is False
    assert body["features"]["uses_https"] is True
    assert body["features"]["query_parameter_count"] == 1


def test_scan_rejects_unsupported_scheme(client):
    response = client.post("/api/scan", json={"url": "javascript:alert(1)"})
    assert response.status_code == 400
    assert "Only HTTP and HTTPS" in response.get_json()["error"]


def test_scan_requires_json_object(client):
    response = client.post("/api/scan", data="[]", content_type="application/json")
    assert response.status_code == 400


def test_scan_requires_url_field(client):
    response = client.post("/api/scan", json={"not_url": "example.com"})
    assert response.status_code == 400


def test_unknown_route_has_json_error(client):
    response = client.get("/missing")
    assert response.status_code == 404
    assert response.get_json()["error"] == "Endpoint not found."


def test_method_not_allowed_returns_json(client):
    response = client.get("/api/scan")
    assert response.status_code == 405
    assert response.get_json()["error"] == "HTTP method not allowed for this endpoint."


def test_scan_rejects_non_string_url(client):
    response = client.post("/api/scan", json={"url": 12345})
    assert response.status_code == 400
    assert "must be a string" in response.get_json()["error"]


def test_request_too_large_returns_json(client):
    large_payload = '{"url": "https://example.com/' + ('x' * 18000) + '"}'
    response = client.post("/api/scan", data=large_payload, content_type="application/json")
    assert response.status_code == 413
    assert response.get_json()["error"] == "Request body is too large."


def test_scan_with_store_scan_history_enabled(tmp_path):
    import hashlib
    import sqlite3
    from backend.app import create_app

    db_path = str(tmp_path / "history_test.sqlite3")
    history_app = create_app({
        "TESTING": True,
        "DEBUG": False,
        "STORE_SCAN_HISTORY": True,
        "DATABASE_PATH": db_path,
        "MAX_URL_LENGTH": 2048,
        "MAX_CONTENT_LENGTH": 16 * 1024,
    })
    history_client = history_app.test_client()

    raw_test_url = "https://example.com/very-secret-token-path"
    response = history_client.post("/api/scan", json={"url": raw_test_url})
    assert response.status_code == 200

    conn = sqlite3.connect(db_path)
    rows = conn.execute("SELECT url_sha256, created_at, features_json, assessment FROM scan_results").fetchall()
    conn.close()

    assert len(rows) == 1
    expected_sha = hashlib.sha256(raw_test_url.encode("utf-8")).hexdigest()
    assert rows[0][0] == expected_sha
    assert rows[0][3] == "not_assessed"
    # Verify raw URL is never stored anywhere in the row
    assert raw_test_url not in rows[0][0]
    assert raw_test_url not in rows[0][2]


def test_production_config_rejects_missing_or_short_secret():
    import pytest
    from backend.app import create_app

    with pytest.raises(RuntimeError, match="PHISHTRACE_SECRET_KEY must be set"):
        create_app({
            "ENV": "production",
            "SECRET_KEY": "short-secret",
            "DEBUG": False,
        })


def test_production_config_rejects_debug_enabled():
    import pytest
    from backend.app import create_app

    with pytest.raises(RuntimeError, match="DEBUG mode must be disabled in production"):
        create_app({
            "ENV": "production",
            "SECRET_KEY": "a" * 32,
            "DEBUG": True,
        })

