"""
routes/url.py
═══════════════════════════════════════════════════════════════════════════
Flask Blueprint exposing the URL phishing analysis endpoint.

This module contains NO detection logic — it only validates the incoming
HTTP request, delegates to the existing `ScamAnalyzer` engine, and shapes
the result into a JSON HTTP response.
"""

from __future__ import annotations

import logging

from flask import Blueprint, jsonify, request

from engine import AnalysisError, ScamAnalyzer

logger = logging.getLogger(__name__)

url_bp = Blueprint("url_bp", __name__)

# A single shared ScamAnalyzer instance for this blueprint (see sms.py for
# rationale — avoids reloading PatternLibrary's JSON files per request).
_analyzer = ScamAnalyzer()


@url_bp.route("/url", methods=["POST"])
def analyze_url():
    """Analyze a URL for phishing indicators.

    Request JSON body:
        {
            "url": "https://example.com"
        }

    Returns:
        200: JSON analysis result from ScamAnalyzer
            {
                "risk_score": int,
                "risk_level": str,
                "category": str,
                "indicators": list[str],
                "recommendations": list[str],
                "explanation": str,
                ...
            }
        400: {"error": "..."} for missing/invalid input.
        500: {"error": "..."} for unexpected engine failures.
    """
    try:
        payload = request.get_json(silent=True)
        url_value = _validate_request(payload)
    except ValueError as exc:
        logger.warning("URL analysis validation failed: %s", exc)
        return jsonify({"error": str(exc)}), 400

    try:
        result = _analyzer.analyze(input_type="url", content=url_value)
        return jsonify(result), 200
    except AnalysisError as exc:
        logger.warning("URL analysis failed: %s", exc)
        return jsonify({"error": str(exc)}), 400
    except Exception:
        logger.exception("Unexpected error during URL analysis.")
        return jsonify({"error": "An unexpected error occurred while analyzing the URL."}), 500


def _validate_request(payload: dict | None) -> str:
    """Validate the incoming JSON payload for the URL analysis endpoint.

    Args:
        payload: The parsed JSON body, or None if parsing failed/missing.

    Returns:
        The validated, non-empty URL string.

    Raises:
        ValueError: If the payload is missing, malformed, or `url` is
            absent, not a string, or empty/whitespace-only.
    """
    if payload is None or not isinstance(payload, dict):
        raise ValueError("Request body must be valid JSON with a 'url' field.")

    url_value = payload.get("url")

    if url_value is None:
        raise ValueError("Field 'url' is required.")

    if not isinstance(url_value, str):
        raise ValueError("Field 'url' must be a string.")

    if not url_value.strip():
        raise ValueError("Field 'url' cannot be empty.")

    return url_value.strip()
