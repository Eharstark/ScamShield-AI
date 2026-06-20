"""
orchestrator.py
═══════════════════════════════════════════════════════════════════════════
The main analysis controller for ScamShield AI. This is the single public
entry point future Flask routes (or any other interface) should call.

Workflow
--------
    Input (sms | url | screenshot)
        │
        ▼
    [screenshot only] OCRProcessor.extract_text()
        │
        ▼
    PatternLibrary.find_all_matches()  ──► urgency / authority / financial / credential hits
        │
        ▼
    URLInspector.inspect()  (if any URL is found in the content, or input_type == "url")
        │
        ▼
    RiskScorer.calculate_score()  ──► numeric score + risk level
        │
        ▼
    ExplanationEngine.generate()  ──► explanation + recommendations + next actions
        │
        ▼
    Final structured result dict

Design notes
------------
- ScamAnalyzer composes (not inherits from) the five other engine classes —
  classic clean-architecture composition over inheritance.
- All dependencies are constructor-injectable, so tests (or a future Flask
  app with a request-scoped lifecycle) can supply mocks/shared instances
  instead of letting ScamAnalyzer construct its own every time.
- A simple regex extracts URLs out of free-form SMS/screenshot text so the
  URLInspector can run even when the user didn't explicitly choose the
  "url" input type.
"""

from __future__ import annotations

import logging
import re
from enum import Enum
from pathlib import Path

from .explanation_engine import ExplanationEngine
from .ocr_processor import OCRProcessor, OCRProcessorError
from .pattern_library import PatternLibrary, PatternLibraryError
from .risk_scorer import RiskScorer
from .url_inspector import URLInspectionResult, URLInspector

logger = logging.getLogger(__name__)


class InputType(str, Enum):
    """Supported analysis input types."""

    SMS = "sms"
    URL = "url"
    SCREENSHOT = "screenshot"


class AnalysisError(Exception):
    """Raised when analysis cannot be completed (bad input, OCR failure, etc.)."""


#: Regex used to pull URLs out of free-form text (SMS bodies, OCR output).
_URL_PATTERN = re.compile(r"(?:https?://|www\.)[^\s<>\"]+", re.IGNORECASE)

#: Maps PatternLibrary match counts -> the "indicator" category name used
#: throughout RiskScorer / ExplanationEngine (keeps a single shared vocabulary
#: across all three modules).
_CATEGORY_NAME_MAP: dict[str, str] = {
    "urgency_keywords": "urgency",
    "authority_names": "authority_impersonation",
    "credential_theft": "credential_theft",
    "financial_lure": "financial_lure",
}

#: Human-readable category labels used for the "category" field in the
#: final result (best-effort classification, highest-weight match wins).
_THREAT_CATEGORY_LABELS: dict[str, str] = {
    "credential_theft": "Credential Theft / Phishing",
    "authority_impersonation": "Banking Scam",
    "financial_lure": "Lottery / Reward Scam",
    "urgency": "Social Engineering",
    "suspicious_url": "Phishing Attack",
    "url_shortener": "Phishing Attack",
}

#: Fallback category label when no indicators were triggered at all.
_DEFAULT_CATEGORY_LABEL = "No Threat Detected"


class ScamAnalyzer:
    """Central orchestrator that runs the full ScamShield AI detection pipeline.

    Usage:
        >>> analyzer = ScamAnalyzer()
        >>> result = analyzer.analyze(
        ...     input_type="sms",
        ...     content="Dear customer, your SBI account will be blocked. Verify now: http://sbi-verify.xyz"
        ... )
        >>> result["risk_score"]
        91
        >>> result["risk_level"]
        'high'
    """

    def __init__(
        self,
        pattern_library: PatternLibrary | None = None,
        url_inspector: URLInspector | None = None,
        risk_scorer: RiskScorer | None = None,
        explanation_engine: ExplanationEngine | None = None,
        ocr_processor: OCRProcessor | None = None,
    ) -> None:
        """Initialize the orchestrator, wiring up (or accepting) all sub-engines.

        Args:
            pattern_library: Shared PatternLibrary instance. Constructed
                fresh (loading bundled JSON patterns) if not provided.
            url_inspector: Shared URLInspector instance. Constructed fresh
                (and wired to `pattern_library`) if not provided.
            risk_scorer: Shared RiskScorer instance. Constructed with
                default weights if not provided.
            explanation_engine: Shared ExplanationEngine instance.
            ocr_processor: Shared OCRProcessor instance. Constructed lazily
                on first screenshot analysis if not provided here, since
                it requires the Tesseract binary to be installed and we
                don't want SMS/URL-only usage to fail just because OCR
                isn't set up.
        """
        self.pattern_library = pattern_library or PatternLibrary()
        self.url_inspector = url_inspector or URLInspector(pattern_library=self.pattern_library)
        self.risk_scorer = risk_scorer or RiskScorer()
        self.explanation_engine = explanation_engine or ExplanationEngine()
        self._ocr_processor = ocr_processor  # lazily constructed, see _get_ocr_processor()

    # ─────────────────────────────────────────────────────────────────
    # Public API
    # ─────────────────────────────────────────────────────────────────

    def analyze(self, input_type: str, content: str) -> dict:
        """Run the full detection pipeline on a single piece of content.

        Args:
            input_type: One of "sms", "url", "screenshot" (case-insensitive).
                - "sms": `content` is the raw message text.
                - "url": `content` is a single URL string.
                - "screenshot": `content` is a filesystem path to an image
                  file; text is extracted via OCR before analysis.
            content: The text, URL, or image file path to analyze, depending
                on `input_type`.

        Returns:
            A dict shaped as:
                {
                    "risk_score": int,            # 0-100
                    "risk_level": str,             # "low" | "medium" | "high"
                    "category": str,               # best-effort threat category label
                    "indicators": list[str],        # human-readable indicator descriptions
                    "recommendations": list[str],
                    "next_actions": list[str],
                    "explanation": str,
                    "extracted_text": str | None,   # populated for screenshot input
                    "source_url_analysis": dict | None,  # populated if a URL was inspected
                    "input_type": str,
                }

        Raises:
            AnalysisError: If `input_type` is invalid, `content` is empty,
                or (for screenshots) OCR extraction fails.
        """
        normalized_type = self._normalize_input_type(input_type)
        self._validate_content(content, normalized_type)

        extracted_text: str | None = None

        # Step 1: Resolve the actual text to analyze.
        if normalized_type is InputType.SCREENSHOT:
            extracted_text = self._extract_text_from_screenshot(content)
            text_to_analyze = extracted_text
        else:
            text_to_analyze = content

        # Step 2: Pattern matching across urgency/authority/financial/credential categories.
        match_counts = self._run_pattern_matching(text_to_analyze)

        # Step 3: URL inspection — either the explicit URL input, or any URL
        # found embedded inside SMS/OCR text.
        url_result = self._run_url_inspection(normalized_type, content, text_to_analyze)

        # Step 4: Weighted risk scoring.
        breakdown = self.risk_scorer.calculate_from_match_counts(
            match_counts=match_counts,
            url_inspection_points=url_result.risk_points if url_result else 0,
            is_url_shortener=bool(url_result and "url_shortener" in url_result.flags),
        )

        # Step 5: Build indicator list + explanation + recommendations.
        indicators = self._build_indicator_descriptions(breakdown.triggered_categories, url_result)
        explanation_payload = self.explanation_engine.build_full_explanation_payload(
            indicators=breakdown.triggered_categories,
            risk_level=breakdown.risk_level.value,
        )

        category_label = self._determine_category_label(breakdown.triggered_categories)

        result = {
            "risk_score": breakdown.score,
            "risk_level": breakdown.risk_level.value,
            "category": category_label,
            "indicators": indicators,
            "recommendations": explanation_payload["recommendations"],
            "next_actions": explanation_payload["next_actions"],
            "explanation": explanation_payload["explanation"],
            "extracted_text": extracted_text,
            "source_url_analysis": url_result.to_dict() if url_result else None,
            "input_type": normalized_type.value,
        }

        logger.info(
            "Analysis complete: type=%s score=%d level=%s category=%s",
            normalized_type.value,
            result["risk_score"],
            result["risk_level"],
            result["category"],
        )
        return result

    # ─────────────────────────────────────────────────────────────────
    # Internal pipeline steps
    # ─────────────────────────────────────────────────────────────────

    @staticmethod
    def _normalize_input_type(input_type: str) -> InputType:
        """Validate and normalize the input_type string into an InputType enum.

        Raises:
            AnalysisError: If input_type is not one of the supported values.
        """
        try:
            return InputType(input_type.strip().lower())
        except (ValueError, AttributeError) as exc:
            valid = ", ".join(t.value for t in InputType)
            raise AnalysisError(f"Invalid input_type '{input_type}'. Must be one of: {valid}") from exc

    @staticmethod
    def _validate_content(content: str, input_type: InputType) -> None:
        """Ensure content is non-empty before running the pipeline.

        Raises:
            AnalysisError: If content is empty/whitespace-only.
        """
        if not content or not content.strip():
            raise AnalysisError(f"Content cannot be empty for input_type '{input_type.value}'.")

    def _extract_text_from_screenshot(self, image_path: str) -> str:
        """Run OCR on a screenshot file path and return extracted text.

        Raises:
            AnalysisError: If OCR extraction fails for any reason.
        """
        processor = self._get_ocr_processor()
        try:
            ocr_result = processor.extract_text(Path(image_path))
        except OCRProcessorError as exc:
            raise AnalysisError(f"Screenshot analysis failed: {exc}") from exc

        if not ocr_result["text"]:
            logger.warning("OCR extracted no text from screenshot: %s", image_path)

        return ocr_result["text"]

    def _get_ocr_processor(self) -> OCRProcessor:
        """Lazily construct the OCRProcessor on first use.

        Deferred so that analyzing SMS/URL content never requires Tesseract
        to be installed — only screenshot analysis does.

        Raises:
            AnalysisError: If pytesseract/Tesseract is not available.
        """
        if self._ocr_processor is None:
            try:
                self._ocr_processor = OCRProcessor()
            except OCRProcessorError as exc:
                raise AnalysisError(f"OCR is not available: {exc}") from exc
        return self._ocr_processor

    def _run_pattern_matching(self, text: str) -> dict[str, int]:
        """Run PatternLibrary matching across all text-based categories.

        Args:
            text: The text to analyze (raw SMS, URL string, or OCR output).

        Returns:
            Dict mapping PatternLibrary category name -> match count, for
            the four text-based categories (urgency, authority, financial,
            credential). TLD/shortener categories are deliberately excluded
            here since those are handled by URLInspector instead.
        """
        try:
            all_matches = self.pattern_library.find_all_matches(
                text,
                categories=["urgency_keywords", "authority_names", "financial_lure", "credential_theft"],
            )
        except PatternLibraryError as exc:
            logger.error("Pattern matching failed: %s", exc)
            return {}

        return {category: len(matches) for category, matches in all_matches.items()}

    def _run_url_inspection(
        self, input_type: InputType, original_content: str, analyzed_text: str
    ) -> URLInspectionResult | None:
        """Determine the URL to inspect (if any) and run URLInspector on it.

        - For input_type == "url", the entire `original_content` is the URL.
        - For "sms"/"screenshot", we scan `analyzed_text` for an embedded URL.
        - If multiple URLs are present, only the first is inspected (MVP scope).

        Returns:
            A URLInspectionResult, or None if no URL was found/applicable.
        """
        if input_type is InputType.URL:
            return self.url_inspector.inspect(original_content.strip())

        found_urls = _URL_PATTERN.findall(analyzed_text or "")
        if not found_urls:
            return None

        return self.url_inspector.inspect(found_urls[0])

    def _build_indicator_descriptions(
        self, triggered_categories: list[str], url_result: URLInspectionResult | None
    ) -> list[str]:
        """Build the final human-readable indicator list for the API response.

        Combines RiskScorer's triggered category names with URLInspector's
        specific reasons (when available) for a richer, more transparent
        indicator list than category names alone.
        """
        labels = {
            "urgency": "Urgency language detected",
            "authority_impersonation": "Authority impersonation detected",
            "credential_theft": "Credential theft attempt detected",
            "financial_lure": "Financial lure detected",
            "suspicious_url": "Suspicious URL detected",
            "url_shortener": "URL shortener detected",
        }

        indicators = [labels[cat] for cat in triggered_categories if cat in labels]

        # Enrich with specific URL reasons, avoiding duplicate generic entries.
        if url_result and url_result.reasons:
            indicators = [i for i in indicators if i not in ("Suspicious URL detected", "URL shortener detected")]
            indicators.extend(url_result.reasons)

        return indicators

    @staticmethod
    def _determine_category_label(triggered_categories: list[str]) -> str:
        """Pick the single best-fit threat category label for the response.

        Priority order matches severity: credential theft is the most
        actionable/dangerous classification, down to generic social
        engineering. Falls back to "No Threat Detected" if nothing fired.
        """
        priority_order = [
            "credential_theft",
            "authority_impersonation",
            "financial_lure",
            "suspicious_url",
            "url_shortener",
            "urgency",
        ]
        for category in priority_order:
            if category in triggered_categories:
                return _THREAT_CATEGORY_LABELS[category]
        return _DEFAULT_CATEGORY_LABEL


# ─────────────────────────────────────────────────────────────────────────
# Quick manual smoke test (run this file directly: `python orchestrator.py`)
# Note: run as `python -m engine.orchestrator` from the project root so the
# relative imports resolve correctly.
# ─────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    analyzer = ScamAnalyzer()

    print("\n" + "=" * 70)
    print("TEST 1: High-risk banking scam SMS")
    print("=" * 70)
    result = analyzer.analyze(
        input_type="sms",
        content=(
            "Dear customer, your SBI account will be suspended immediately. "
            "Verify now and share your UPI PIN to avoid permanent block. "
            "Click here: http://sbi-verify-account.xyz/login"
        ),
    )
    for key, value in result.items():
        print(f"\n[{key}]")
        print(value)

    print("\n" + "=" * 70)
    print("TEST 2: Plain URL analysis")
    print("=" * 70)
    result2 = analyzer.analyze(input_type="url", content="http://login.secure.update-sbi.tk/verify")
    print("risk_score:", result2["risk_score"], " risk_level:", result2["risk_level"], " category:", result2["category"])

    print("\n" + "=" * 70)
    print("TEST 3: Benign message (should be low risk)")
    print("=" * 70)
    result3 = analyzer.analyze(input_type="sms", content="Hey, are we still on for lunch tomorrow at 1pm?")
    print("risk_score:", result3["risk_score"], " risk_level:", result3["risk_level"], " category:", result3["category"])
