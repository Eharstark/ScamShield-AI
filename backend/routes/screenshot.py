"""
routes/screenshot.py
═══════════════════════════════════════════════════════════════════════════
Flask Blueprint exposing the screenshot scam analysis endpoint.

This module contains NO detection/OCR logic — it only validates and saves
the uploaded file, delegates to the existing `ScamAnalyzer` engine (which
internally runs OCRProcessor), shapes the result into a JSON HTTP response,
and cleans up the temporary uploaded file afterward.

Workflow
--------
    multipart/form-data upload (field "file")
        │
        ▼
    Validate file presence + extension
        │
        ▼
    Save to uploads/ with a safe, collision-resistant filename
        │
        ▼
    ScamAnalyzer.analyze(input_type="screenshot", content=file_path)
        │
        ▼
    Return JSON result
        │
        ▼
    Delete the temporary file (always, even on failure)
"""

from __future__ import annotations

import logging
import os
import uuid

from flask import Blueprint, current_app, jsonify, request
from werkzeug.datastructures import FileStorage
from werkzeug.utils import secure_filename

from engine import AnalysisError, ScamAnalyzer

logger = logging.getLogger(__name__)

screenshot_bp = Blueprint("screenshot_bp", __name__)

# A single shared ScamAnalyzer instance for this blueprint (see sms.py for
# rationale). Note: OCRProcessor is constructed lazily inside ScamAnalyzer
# on first screenshot request, so app startup never requires Tesseract to
# be installed unless this endpoint is actually used.
_analyzer = ScamAnalyzer()

#: File extensions accepted for screenshot uploads (case-insensitive).
ALLOWED_EXTENSIONS: frozenset[str] = frozenset({"png", "jpg", "jpeg", "webp"})


def allowed_file(filename: str) -> bool:
    """Check whether a filename has an allowed image extension.

    Args:
        filename: The original filename from the upload (may be unsafe;
            this function only inspects the extension, it doesn't sanitize).

    Returns:
        True if the filename has a dot and the extension (lowercased) is
        in ALLOWED_EXTENSIONS, False otherwise.
    """
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@screenshot_bp.route("/screenshot", methods=["POST"])
def analyze_screenshot():
    """Analyze an uploaded screenshot for scam indicators via OCR + detection.

    Request: multipart/form-data with a "file" field containing the image.

    Returns:
        200: JSON analysis result from ScamAnalyzer
            {
                "risk_score": int,
                "risk_level": str,
                "category": str,
                "indicators": list[str],
                "recommendations": list[str],
                "explanation": str,
                "extracted_text": str,
                ...
            }
        400: {"error": "..."} for missing file / unsupported extension.
        500: {"error": "..."} for unexpected engine/OCR failures.
    """
    try:
        upload = _validate_upload(request.files)
    except ValueError as exc:
        logger.warning("Screenshot analysis validation failed: %s", exc)
        return jsonify({"error": str(exc)}), 400

    saved_path = _save_upload(upload)

    try:
        result = _analyzer.analyze(input_type="screenshot", content=saved_path)
        return jsonify(result), 200
    except AnalysisError as exc:
        logger.warning("Screenshot analysis failed: %s", exc)
        return jsonify({"error": str(exc)}), 400
    except Exception:
        logger.exception("Unexpected error during screenshot analysis.")
        return jsonify({"error": "An unexpected error occurred while analyzing the screenshot."}), 500
    finally:
        # Always clean up the temporary file, whether analysis succeeded,
        # failed validation inside the engine, or raised unexpectedly.
        _delete_temp_file(saved_path)


def _validate_upload(files) -> FileStorage:
    """Validate that a supported image file was included in the request.

    Args:
        files: The Flask `request.files` MultiDict.

    Returns:
        The validated FileStorage object for the "file" field.

    Raises:
        ValueError: If no file was provided, the filename is empty, or the
            extension is not in ALLOWED_EXTENSIONS.
    """
    if "file" not in files:
        raise ValueError("No file part in the request. Expected a 'file' field in form-data.")

    upload = files["file"]

    if upload.filename is None or upload.filename.strip() == "":
        raise ValueError("No file selected for upload.")

    if not allowed_file(upload.filename):
        allowed = ", ".join(sorted(ALLOWED_EXTENSIONS))
        raise ValueError(f"Unsupported file type. Allowed extensions: {allowed}.")

    return upload


def _save_upload(upload: FileStorage) -> str:
    """Save an uploaded file into the configured uploads folder safely.

    Generates a UUID-prefixed filename to avoid collisions between
    concurrent uploads and to neutralize any path-traversal attempts in
    the original filename (on top of `secure_filename`'s own sanitization).

    Args:
        upload: The validated FileStorage object to save.

    Returns:
        The absolute filesystem path the file was saved to.
    """
    safe_name = secure_filename(upload.filename)
    unique_name = f"{uuid.uuid4().hex}_{safe_name}"

    upload_folder = current_app.config["UPLOAD_FOLDER"]
    destination_path = os.path.join(upload_folder, unique_name)

    upload.save(destination_path)
    logger.info("Saved uploaded screenshot to: %s", destination_path)

    return destination_path


def _delete_temp_file(file_path: str) -> None:
    """Delete a temporary uploaded file, logging but not raising on failure.

    Cleanup failures shouldn't crash the response — the analysis result
    has already been computed and should still reach the client.

    Args:
        file_path: Absolute path to the file to delete.
    """
    try:
        if os.path.exists(file_path):
            os.remove(file_path)
            logger.info("Deleted temporary screenshot: %s", file_path)
    except OSError as exc:
        logger.warning("Failed to delete temporary file %s: %s", file_path, exc)
