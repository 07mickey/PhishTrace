"""Health-check endpoint."""
from flask import Blueprint, jsonify

health_bp = Blueprint("health", __name__)


@health_bp.get("/api/health")
def health_check():
    return jsonify({"service": "PhishTrace API", "status": "ok"}), 200
