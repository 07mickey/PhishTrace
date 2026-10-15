"""URL scan endpoint. This route never fetches the submitted URL."""
from flask import Blueprint, current_app, jsonify, request

from backend.extensions import save_scan_result
from backend.models import ScanResult
from backend.schemas.scan_schema import validate_scan_payload
from backend.services.feature_extractor import extract_url_features
from backend.services.url_validator import validate_and_normalize_url

scan_bp = Blueprint("scan", __name__)


@scan_bp.post("/api/scan")
def scan_url():
    payload = request.get_json(silent=True)
    try:
        raw_url = validate_scan_payload(payload)
        normalized_url = validate_and_normalize_url(
            raw_url, max_length=current_app.config["MAX_URL_LENGTH"]
        )
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    features = extract_url_features(normalized_url)
    result = ScanResult.from_url(normalized_url, features)

    if current_app.config.get("STORE_SCAN_HISTORY", False):
        save_scan_result(result)

    return jsonify({
        "status": "features_extracted",
        "url": normalized_url,
        "assessment": {
            "label": result.assessment,
            "message": (
                "URL structure features were extracted, but the phishing detection "
                "engine is not integrated. This is not a safety verdict."
            ),
        },
        "detection_engine": {"integrated": False},
        "features": features,
    }), 200
