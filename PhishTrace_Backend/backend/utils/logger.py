"""Basic application logging without logging submitted URLs."""
import logging


def configure_logging(app) -> None:
    if not app.logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)s %(name)s: %(message)s"
        ))
        app.logger.addHandler(handler)
    app.logger.setLevel(logging.INFO)
