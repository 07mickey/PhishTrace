"""PhishTrace Flask application factory and local entry point."""
from __future__ import annotations

from flask import Flask

from backend.config import Config
from backend.extensions import init_app as init_extensions
from backend.routes.health import health_bp
from backend.routes.scan import scan_bp
from backend.utils.error_handlers import register_error_handlers
from backend.utils.logger import configure_logging


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.config.from_object(Config)
    if test_config:
        app.config.update(test_config)

    if app.config.get("ENV") == "production":
        secret_key = app.config.get("SECRET_KEY")
        if not secret_key or len(secret_key) < 32:
            raise RuntimeError(
                "PHISHTRACE_SECRET_KEY must be set to a high-entropy value of at least 32 characters in production."
            )
        if app.config.get("DEBUG"):
            raise RuntimeError("DEBUG mode must be disabled in production.")

    configure_logging(app)
    init_extensions(app)
    app.register_blueprint(health_bp)
    app.register_blueprint(scan_bp)
    register_error_handlers(app)
    return app


app = create_app()


if __name__ == "__main__":
    app.run(
        host=app.config["HOST"],
        port=app.config["PORT"],
        debug=app.config["DEBUG"],
    )
