"""Consistent JSON error responses."""
from flask import jsonify


def register_error_handlers(app) -> None:
    @app.errorhandler(400)
    def bad_request(_error):
        return jsonify({"error": "The request is invalid."}), 400

    @app.errorhandler(404)
    def not_found(_error):
        return jsonify({"error": "Endpoint not found."}), 404

    @app.errorhandler(405)
    def method_not_allowed(_error):
        return jsonify({"error": "HTTP method not allowed for this endpoint."}), 405

    @app.errorhandler(413)
    def request_too_large(_error):
        return jsonify({"error": "Request body is too large."}), 413

    @app.errorhandler(500)
    def internal_error(_error):
        app.logger.exception("Unhandled application error")
        return jsonify({"error": "An internal server error occurred."}), 500
