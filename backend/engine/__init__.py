"""
engine
═══════════════════════════════════════════════════════════════════════════
ScamShield AI — Detection Engine package.

This package contains the complete rule-based scam detection engine:
pattern matching, URL inspection, OCR text extraction, weighted risk
scoring, human-readable explanation generation, and the orchestrator
that ties them all together.

No external AI APIs (OpenAI/Claude/etc.) are used. Everything here runs
locally and deterministically, which makes it fast, free, offline-capable,
and fully explainable — ideal for a hackathon demo and a defensible MVP.

Public API
----------
Import the pieces you need directly from `engine`:

    from engine import ScamAnalyzer

    analyzer = ScamAnalyzer()
    result = analyzer.analyze(input_type="sms", content="Your account will be blocked...")
    print(result["risk_score"], result["risk_level"])

Module map
----------
- pattern_library.py     -> PatternLibrary, PatternMatch, PatternLibraryError
- url_inspector.py        -> URLInspector, URLInspectionResult
- risk_scorer.py          -> RiskScorer, RiskBreakdown
- explanation_engine.py   -> ExplanationEngine
- ocr_processor.py        -> OCRProcessor, OCRProcessorError
- orchestrator.py         -> ScamAnalyzer (the main entry point)
"""

from __future__ import annotations

from .pattern_library import (
    PatternLibrary,
    PatternLibraryError,
    PatternMatch,
    PatternSet,
)
from .url_inspector import URLInspectionResult, URLInspector
from .risk_scorer import RiskBreakdown, RiskScorer
from .explanation_engine import ExplanationEngine
from .ocr_processor import OCRProcessor, OCRProcessorError
from .orchestrator import ScamAnalyzer, AnalysisError, InputType

__all__ = [
    # Orchestrator (primary entry point)
    "ScamAnalyzer",
    "AnalysisError",
    "InputType",
    # Pattern library
    "PatternLibrary",
    "PatternLibraryError",
    "PatternMatch",
    "PatternSet",
    # URL inspection
    "URLInspector",
    "URLInspectionResult",
    # Risk scoring
    "RiskScorer",
    "RiskBreakdown",
    # Explanation generation
    "ExplanationEngine",
    # OCR
    "OCRProcessor",
    "OCRProcessorError",
]

__version__ = "1.0.0"
