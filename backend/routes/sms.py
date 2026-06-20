"""
routes/sms.py
═══════════════════════════════════════════════════════════════════════════
Flask Blueprint exposing the SMS scam analysis endpoint.

This module contains NO detection logic — it only validates the incoming
HTTP request, delegates to the existing `ScamAnalyzer` engine, and shapes
the result into a JSON HTTP response.
"""

from __future__ import annotations

import logging

from flask import Blueprint, jsonify, request

from engine import AnalysisError, ScamAnalyzer

logger = logging.getLogger(__name__)

sms_bp = Blueprint("sms_bp", __name__)

# A single shared ScamAnalyzer instance for this blueprint. PatternLibrary
# loads JSON pattern files at construction time, so reusing one instance
# across requests avoids re-reading those files on every call.
_analyzer = ScamAnalyzer()


@sms_bp.route("/sms", methods=["POST"])
def analyze_sms():
    """Analyze an SMS message for scam indicators.

    Request JSON body:
        {
            "message": "Your account will be suspended..."
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
        message = _validate_request(payload)
    except ValueError as exc:
        logger.warning("SMS analysis validation failed: %s", exc)
        return jsonify({"error": str(exc)}), 400

    try:
        result = _analyzer.analyze(input_type="sms", content=message)
        return jsonify(result), 200
    except AnalysisError as exc:
        # Known, expected failure from the engine (e.g. bad input it caught
        # internally) — treat as a client error since it stems from input.
        logger.warning("SMS analysis failed: %s", exc)
        return jsonify({"error": str(exc)}), 400
    except Exception:
        # Anything unexpected — never leak internals to the client.
        logger.exception("Unexpected error during SMS analysis.")
        return jsonify({"error": "An unexpected error occurred while analyzing the message."}), 500


def _validate_request(payload: dict | None) -> str:
    """Validate the incoming JSON payload for the SMS analysis endpoint.

    Args:
        payload: The parsed JSON body, or None if parsing failed/missing.

    Returns:
        The validated, non-empty message string.

    Raises:
        ValueError: If the payload is missing, malformed, or `message` is
            absent, not a string, or empty/whitespace-only.
    """
    if payload is None or not isinstance(payload, dict):
        raise ValueError("Request body must be valid JSON with a 'message' field.")

    message = payload.get("message")

    if message is None:
        raise ValueError("Field 'message' is required.")

    if not isinstance(message, str):
        raise ValueError("Field 'message' must be a string.")

    if not message.strip():
        raise ValueError("Field 'message' cannot be empty.")

    return message
