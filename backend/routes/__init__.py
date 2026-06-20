"""
routes
═══════════════════════════════════════════════════════════════════════════
Flask Blueprint package for ScamShield AI's API layer.

Each module exposes a single Blueprint:
    - sms.py        -> sms_bp        (POST /api/analyze/sms)
    - url.py         -> url_bp        (POST /api/analyze/url)
    - screenshot.py  -> screenshot_bp (POST /api/analyze/screenshot)

These Blueprints are registered onto the Flask app in app.py.
"""
