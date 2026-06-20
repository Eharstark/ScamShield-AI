"""
risk_scorer.py
═══════════════════════════════════════════════════════════════════════════
Responsible for converting raw detection signals (pattern matches + URL
inspection flags) into a single weighted risk score from 0-100, plus a
categorical risk level and a transparent per-category breakdown.

Design notes
------------
- Weights are configurable at construction time, so a hackathon team can
  tune sensitivity without touching the scoring logic itself.
- The score is always clamped to [0, 100] — no category can push the
  total out of range, and the sum of all categories is capped at the end.
- `calculate_score()` returns both the simple {"score", "risk_level"} shape
  requested in the spec AND a full RiskBreakdown object for callers (like
  the orchestrator) that want per-category transparency for explanations.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class RiskLevel(str, Enum):
    """Categorical risk level derived from the numeric score."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @classmethod
    def from_score(cls, score: int) -> "RiskLevel":
        """Map a 0-100 score onto a RiskLevel using the project's thresholds.

        Thresholds:
            0-30   -> low
            31-70  -> medium
            71-100 -> high
        """
        if score <= 30:
            return cls.LOW
        if score <= 70:
            return cls.MEDIUM
        return cls.HIGH


@dataclass
class RiskBreakdown:
    """Full, transparent result of a risk scoring pass.

    Attributes:
        score: Final clamped risk score, 0-100.
        risk_level: Categorical level derived from `score`.
        category_points: Raw (pre-cap) points awarded per scoring category,
            e.g. {"urgency": 15, "authority_impersonation": 20, ...}.
        triggered_categories: Names of categories that contributed > 0 points,
            in the order they were evaluated. Useful for explanation generation.
        raw_total: Sum of all category points *before* clamping to 100 —
            useful for debugging/tuning weights even when the displayed
            score is capped.
    """

    score: int
    risk_level: RiskLevel
    category_points: dict[str, int] = field(default_factory=dict)
    triggered_categories: list[str] = field(default_factory=list)
    raw_total: int = 0

    def to_dict(self) -> dict:
        """Serialize to the simple {"score", "risk_level"} shape plus extras.

        The base "score" / "risk_level" keys match the spec exactly; the
        additional keys are there for callers that want the full breakdown
        (e.g. the orchestrator building its "indicators" list).
        """
        return {
            "score": self.score,
            "risk_level": self.risk_level.value,
            "category_points": dict(self.category_points),
            "triggered_categories": list(self.triggered_categories),
        }


class RiskScorer:
    """Weighted, configurable risk scoring engine.

    Usage:
        >>> scorer = RiskScorer()
        >>> breakdown = scorer.calculate_score(
        ...     urgency_hits=2,
        ...     authority_hits=1,
        ...     credential_theft_hits=1,
        ...     financial_lure_hits=0,
        ...     url_risk_points=25,
        ...     is_url_shortener=False,
        ... )
        >>> breakdown.score
        85
        >>> breakdown.risk_level
        <RiskLevel.HIGH: 'high'>
    """

    # ── Default category weights (points awarded per category if ANY
    # match in that category is found — these are flat "category present"
    # weights per the spec, not per-keyword-occurrence weights). ─────────
    DEFAULT_WEIGHTS: dict[str, int] = {
        "urgency": 15,
        "authority_impersonation": 20,
        "credential_theft": 25,
        "financial_lure": 15,
        "suspicious_url": 25,
        "url_shortener": 10,
    }

    #: Risk score is always clamped into this inclusive range.
    MIN_SCORE: int = 0
    MAX_SCORE: int = 100

    def __init__(self, weights: dict[str, int] | None = None) -> None:
        """Initialize the scorer with optional custom weights.

        Args:
            weights: Optional override for any subset of DEFAULT_WEIGHTS
                category weights. Unspecified categories fall back to the
                default. This lets a hackathon team A/B test sensitivity
                without editing source code.
        """
        self.weights: dict[str, int] = {**self.DEFAULT_WEIGHTS, **(weights or {})}
        logger.debug("RiskScorer initialized with weights: %s", self.weights)

    # ─────────────────────────────────────────────────────────────────
    # Public API
    # ─────────────────────────────────────────────────────────────────

    def calculate_score(
        self,
        *,
        urgency_hits: int = 0,
        authority_hits: int = 0,
        credential_theft_hits: int = 0,
        financial_lure_hits: int = 0,
        url_risk_points: int = 0,
        is_url_shortener: bool = False,
    ) -> RiskBreakdown:
        """Calculate the final weighted risk score from raw signal counts.

        Each *_hits argument represents how many pattern matches were found
        for that category (from PatternLibrary.find_matches()). A category
        contributes its full weight if hits > 0 — i.e. weighting is
        "presence-based" per the spec (urgency present = +15, regardless of
        whether it appeared once or five times). This keeps scoring
        predictable and avoids one repeated keyword dominating the score.

        Args:
            urgency_hits: Number of urgency-keyword matches found.
            authority_hits: Number of authority-impersonation matches found.
            credential_theft_hits: Number of credential-theft phrase matches found.
            financial_lure_hits: Number of financial-lure phrase matches found.
            url_risk_points: Risk points contributed by URLInspector for any
                URL(s) found in the content (already 0-35 capped per URL by
                URLInspector; this scorer folds it into "suspicious_url").
            is_url_shortener: Whether a detected URL is a known shortener
                (folded into the separate "url_shortener" category so it can
                stack with "suspicious_url" but is weighted independently).

        Returns:
            A RiskBreakdown with the final clamped score, risk level, and
            full per-category transparency.
        """
        category_points: dict[str, int] = {}

        if urgency_hits > 0:
            category_points["urgency"] = self.weights["urgency"]

        if authority_hits > 0:
            category_points["authority_impersonation"] = self.weights["authority_impersonation"]

        if credential_theft_hits > 0:
            category_points["credential_theft"] = self.weights["credential_theft"]

        if financial_lure_hits > 0:
            category_points["financial_lure"] = self.weights["financial_lure"]

        if url_risk_points > 0:
            category_points["suspicious_url"] = self.weights["suspicious_url"]

        if is_url_shortener:
            category_points["url_shortener"] = self.weights["url_shortener"]

        raw_total = sum(category_points.values())
        clamped_score = max(self.MIN_SCORE, min(self.MAX_SCORE, raw_total))
        risk_level = RiskLevel.from_score(clamped_score)

        breakdown = RiskBreakdown(
            score=clamped_score,
            risk_level=risk_level,
            category_points=category_points,
            triggered_categories=list(category_points.keys()),
            raw_total=raw_total,
        )

        logger.info(
            "Risk calculated: score=%d level=%s categories=%s",
            breakdown.score,
            breakdown.risk_level.value,
            breakdown.triggered_categories,
        )
        return breakdown

    def calculate_from_match_counts(self, match_counts: dict[str, int], url_inspection_points: int = 0, is_url_shortener: bool = False) -> RiskBreakdown:
        """Convenience wrapper for callers holding a PatternLibrary-style match-count dict.

        Args:
            match_counts: Dict keyed by PatternLibrary category names
                (e.g. "urgency_keywords", "authority_names",
                "credential_theft", "financial_lure") mapping to how many
                matches were found in each.
            url_inspection_points: Risk points from URLInspector for any URL
                found in the content.
            is_url_shortener: Whether a detected URL is a known shortener.

        Returns:
            A RiskBreakdown, same as calculate_score().
        """
        return self.calculate_score(
            urgency_hits=match_counts.get("urgency_keywords", 0),
            authority_hits=match_counts.get("authority_names", 0),
            credential_theft_hits=match_counts.get("credential_theft", 0),
            financial_lure_hits=match_counts.get("financial_lure", 0),
            url_risk_points=url_inspection_points,
            is_url_shortener=is_url_shortener,
        )

    def explain_weights(self) -> dict[str, int]:
        """Return the active weight configuration (useful for API docs/debugging)."""
        return dict(self.weights)


# ─────────────────────────────────────────────────────────────────────────
# Quick manual smoke test (run this file directly: `python risk_scorer.py`)
# ─────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    scorer = RiskScorer()

    print("Active weights:", scorer.explain_weights())

    # Simulate a high-risk banking scam SMS
    high_risk = scorer.calculate_score(
        urgency_hits=3,
        authority_hits=1,
        credential_theft_hits=2,
        financial_lure_hits=1,
        url_risk_points=30,
        is_url_shortener=False,
    )
    print("\nHigh-risk example:", high_risk.to_dict())

    # Simulate a low-risk, mostly benign message
    low_risk = scorer.calculate_score(
        urgency_hits=0,
        authority_hits=0,
        credential_theft_hits=0,
        financial_lure_hits=0,
        url_risk_points=0,
        is_url_shortener=False,
    )
    print("Low-risk example:", low_risk.to_dict())

    # Simulate a medium-risk case: just urgency + a shortener
    medium_risk = scorer.calculate_score(
        urgency_hits=1,
        authority_hits=0,
        credential_theft_hits=0,
        financial_lure_hits=0,
        url_risk_points=0,
        is_url_shortener=True,
    )
    print("Medium-risk example:", medium_risk.to_dict())
