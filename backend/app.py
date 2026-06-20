"""
app.py
═══════════════════════════════════════════════════════════════════════════
ScamShield AI — Flask application entry point.

Responsibilities
-----------------
- Construct and configure the Flask application instance.
- Enable CORS so the frontend (served from a different origin/port during
  development) can call these APIs.
- Configure the uploads folder used by the screenshot analysis endpoint.
- Register all route Blueprints (sms, url, screenshot).
- Expose a health-check endpoint for uptime monitoring / quick sanity checks.

This file deliberately contains NO detection logic — it only wires together
the existing `engine` package (untouched) with the Flask route layer in
`routes/`. Separation of concerns: app.py = wiring, routes/* = HTTP
contract, engine/* = business logic.
"""

from __future__ import annotations

import logging
import os

from flask import Flask, jsonify
from flask_cors import CORS

from routes.screenshot import screenshot_bp
from routes.sms import sms_bp
from routes.url import url_bp

logger = logging.getLogger(__name__)


def create_app() -> Flask:
    """Application factory: builds and configures the Flask app instance.

    Using the application-factory pattern (rather than a bare module-level
    `app = Flask(__name__)`) keeps the app testable — a test suite can call
    `create_app()` multiple times with different configs without import-order
    side effects.

    Returns:
        A fully configured Flask application, ready to run or be served by
        a WSGI server (gunicorn, etc.).
    """
    app = Flask(__name__)

    _configure_logging()
    _configure_uploads(app)

    # Enable CORS for all /api/* routes. In a real production deployment,
    # `origins` should be restricted to the actual frontend domain(s)
    # rather than left wide open.
    CORS(app, resources={r"/api/*": {"origins": "*"}})

    _register_blueprints(app)
    _register_health_endpoint(app)
    _register_error_handlers(app)

    logger.info("ScamShield AI Flask app created successfully.")
    return app


# ─────────────────────────────────────────────────────────────────────────
# Configuration helpers
# ─────────────────────────────────────────────────────────────────────────

def _configure_logging() -> None:
    """Set up basic application-wide logging."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )


def _configure_uploads(app: Flask) -> None:
    """Configure the uploads folder used by the screenshot analysis route.

    The folder is created on startup if it doesn't already exist, so a
    fresh clone of the repo works without manual setup steps.

    Args:
        app: The Flask application instance to configure.
    """
    uploads_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")
    os.makedirs(uploads_dir, exist_ok=True)

    app.config["UPLOAD_FOLDER"] = uploads_dir
    # 8 MB cap on uploaded screenshots — generous for phone screenshots,
    # tight enough to prevent abuse of the analysis endpoint.
    app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024

    logger.info("Uploads folder configured at: %s", uploads_dir)


def _register_blueprints(app: Flask) -> None:
    """Register all route Blueprints onto the Flask app.

    Args:
        app: The Flask application instance to register routes on.
    """
    app.register_blueprint(sms_bp, url_prefix="/api/analyze")
    app.register_blueprint(url_bp, url_prefix="/api/analyze")
    app.register_blueprint(screenshot_bp, url_prefix="/api/analyze")
    logger.info("Registered blueprints: sms_bp, url_bp, screenshot_bp")


def _register_health_endpoint(app: Flask) -> None:
    """Register the GET /api/health endpoint.

    Args:
        app: The Flask application instance to register the route on.
    """

    @app.route("/api/health", methods=["GET"])
    def health_check():
        """Simple liveness/readiness probe.

        Returns:
            JSON: {"status": "online", "service": "ScamShield AI Backend"}
        """
        return jsonify({"status": "online", "service": "ScamShield AI Backend"}), 200


def _register_error_handlers(app: Flask) -> None:
    """Register application-wide JSON error handlers for common HTTP errors.

    Without these, Flask's default error handlers return HTML, which is
    inconvenient for a JSON API consumed by a frontend.

    Args:
        app: The Flask application instance to register handlers on.
    """

    @app.errorhandler(404)
    def handle_not_found(error):
        return jsonify({"error": "The requested endpoint does not exist."}), 404

    @app.errorhandler(405)
    def handle_method_not_allowed(error):
        return jsonify({"error": "This HTTP method is not allowed for this endpoint."}), 405

    @app.errorhandler(413)
    def handle_payload_too_large(error):
        return jsonify({"error": "Uploaded file exceeds the maximum allowed size (8 MB)."}), 413

    @app.errorhandler(500)
    def handle_internal_error(error):
        logger.exception("Unhandled internal server error.")
        return jsonify({"error": "An unexpected internal server error occurred."}), 500


# ─────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────
app = create_app()

if __name__ == "__main__":
    app.run(debug=True)
