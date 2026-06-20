"""
explanation_engine.py
═══════════════════════════════════════════════════════════════════════════
Responsible for translating raw technical findings (triggered pattern
categories, URL inspection flags, risk level) into a single, coherent,
human-readable explanation paragraph — plus a list of actionable security
recommendations and "next action" steps.

Design notes
------------
- Templated, not generative: every sentence fragment is hand-written and
  category-specific, so output is deterministic, fast, and never
  hallucinates. This is what makes the engine work entirely offline
  without an LLM.
- Fragments are composed in a fixed, readable priority order (most
  dangerous signal first) rather than the order categories happen to be
  triggered in, so the resulting sentence always reads naturally.
- Recommendations are deduplicated and ordered by relevance to the
  specific indicators found, with a baseline set of universal tips always
  included.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


class ExplanationEngine:
    """Generates human-readable explanations and recommendations from indicators.

    Usage:
        >>> engine = ExplanationEngine()
        >>> text = engine.generate(["urgency", "authority_impersonation", "suspicious_url"])
        >>> print(text)
        This message attempts to create urgency while impersonating a
        trusted authority and directs users to a suspicious link. These
        are common phishing techniques used to pressure victims into
        acting before they think carefully.
    """

    # ── Human-readable fragments per category, used to build the main
    # explanation sentence. Ordered by typical severity / narrative flow. ──
    CATEGORY_FRAGMENTS: dict[str, str] = {
        "urgency": "creates a false sense of urgency to rush the reader into acting without thinking",
        "authority_impersonation": "impersonates a trusted authority or well-known institution to appear legitimate",
        "credential_theft": "directly asks for sensitive credentials such as an OTP, PIN, password, or card details",
        "financial_lure": "dangles a financial reward, prize, or refund to bait the reader into engaging",
        "suspicious_url": "directs the reader to a suspicious or deceptive link",
        "url_shortener": "hides the true destination behind a shortened URL",
    }

    # ── Category-specific security recommendations. A category can map
    # to multiple recommendations; duplicates across categories are
    # deduplicated when assembled. ──────────────────────────────────────
    CATEGORY_RECOMMENDATIONS: dict[str, list[str]] = {
        "urgency": [
            "Pause before acting — legitimate organizations rarely demand immediate action.",
            "Take time to verify the request through an independent, trusted channel.",
        ],
        "authority_impersonation": [
            "Verify the sender through the organization's official website or app, not the contact info given in the message.",
            "Contact the organization directly using a phone number from their official website.",
        ],
        "credential_theft": [
            "Never share your OTP, PIN, CVV, or password with anyone, including someone claiming to be from your bank.",
            "Legitimate banks and institutions never ask for your PIN or OTP over SMS, call, or email.",
        ],
        "financial_lure": [
            "Be skeptical of unexpected prizes, refunds, or rewards you did not request.",
            "If it sounds too good to be true, it almost certainly is.",
        ],
        "suspicious_url": [
            "Do not click on suspicious or unfamiliar links.",
            "Manually type the official website address into your browser instead of clicking a link.",
        ],
        "url_shortener": [
            "Avoid clicking shortened links from unknown senders — expand them with a URL-preview tool first if you must check them.",
        ],
    }

    #: Recommendations shown regardless of which specific indicators were found.
    BASELINE_RECOMMENDATIONS: list[str] = [
        "Never share your OTP or PIN with anyone, under any circumstance.",
        "When in doubt, verify through official channels before taking any action.",
        "Report suspicious messages to your bank and to cybercrime.gov.in.",
    ]

    # ── Risk-level specific "next action" guidance ──────────────────────
    NEXT_ACTIONS_BY_LEVEL: dict[str, list[str]] = {
        "high": [
            "Do not click any links, reply, or share any information.",
            "Block and report the sender immediately.",
            "If you already shared details, contact your bank's fraud helpline right now.",
        ],
        "medium": [
            "Proceed with caution and verify the source before taking any action.",
            "Avoid entering any personal or financial information until verified.",
        ],
        "low": [
            "No immediate threat detected, but always stay alert for unexpected requests.",
            "Continue practicing standard digital hygiene (unique passwords, 2FA, etc.).",
        ],
    }

    #: Fallback explanation used when no indicators were triggered at all.
    NO_INDICATORS_EXPLANATION: str = (
        "No strong scam indicators were detected in this content. It does not "
        "match common patterns of urgency, authority impersonation, credential "
        "theft, financial lures, or suspicious links. However, the absence of "
        "these signals does not guarantee the content is completely safe — "
        "always stay cautious with unfamiliar senders and requests."
    )

    def __init__(self) -> None:
        """Initialize the explanation engine. Currently stateless, kept as a
        class (rather than module-level functions) so it can later hold
        configuration (e.g. localization, tone settings) without changing
        the public API used by the orchestrator.
        """
        pass

    # ─────────────────────────────────────────────────────────────────
    # Public API
    # ─────────────────────────────────────────────────────────────────

    def generate(self, indicators: list[str]) -> str:
        """Generate a single human-readable explanation paragraph.

        Args:
            indicators: List of triggered category names (e.g.
                ["urgency", "authority_impersonation", "suspicious_url"]).
                Unrecognized category names are silently ignored so the
                engine never crashes on unexpected input.

        Returns:
            A natural-language paragraph summarizing why the content was
            flagged, or a reassuring fallback message if no indicators
            were provided.
        """
        if not indicators:
            return self.NO_INDICATORS_EXPLANATION

        # Preserve a stable, readable priority order regardless of input order.
        ordered = [cat for cat in self.CATEGORY_FRAGMENTS if cat in indicators]
        fragments = [self.CATEGORY_FRAGMENTS[cat] for cat in ordered]

        if not fragments:
            return self.NO_INDICATORS_EXPLANATION

        sentence = self._join_fragments(fragments)
        closing = self._closing_statement(ordered)

        return f"This content {sentence}. {closing}"

    def get_recommendations(self, indicators: list[str]) -> list[str]:
        """Build a deduplicated, relevance-ordered list of security recommendations.

        Args:
            indicators: List of triggered category names.

        Returns:
            A list of recommendation strings: category-specific tips first
            (in the order their categories appear in CATEGORY_FRAGMENTS),
            followed by universal baseline tips. Duplicates are removed
            while preserving first-seen order.
        """
        ordered = [cat for cat in self.CATEGORY_FRAGMENTS if cat in indicators]

        recommendations: list[str] = []
        for category in ordered:
            recommendations.extend(self.CATEGORY_RECOMMENDATIONS.get(category, []))
        recommendations.extend(self.BASELINE_RECOMMENDATIONS)

        return self._deduplicate(recommendations)

    def get_next_actions(self, risk_level: str) -> list[str]:
        """Return risk-level-appropriate "what to do right now" steps.

        Args:
            risk_level: One of "low", "medium", "high" (case-insensitive).
                Unknown values fall back to the "medium" action set as a
                safe default.

        Returns:
            A list of concrete next-action strings.
        """
        normalized = risk_level.strip().lower()
        return list(self.NEXT_ACTIONS_BY_LEVEL.get(normalized, self.NEXT_ACTIONS_BY_LEVEL["medium"]))

    def get_security_tips(self) -> list[str]:
        """Return general, content-independent security awareness tips.

        Useful for populating a static "Security Tips" panel in the UI
        regardless of any specific analysis result.
        """
        return [
            "Banks and government agencies never ask for your OTP, PIN, or password over SMS or call.",
            "Always verify links by typing the official website address directly into your browser.",
            "Enable two-factor authentication on all your financial and email accounts.",
            "Be suspicious of any message that pressures you to act immediately.",
            "If an offer seems too good to be true, it probably is.",
        ]

    def build_full_explanation_payload(self, indicators: list[str], risk_level: str) -> dict:
        """Convenience method bundling explanation + recommendations + next actions.

        Args:
            indicators: List of triggered category names.
            risk_level: The overall risk level string ("low" | "medium" | "high").

        Returns:
            A dict with keys: "explanation", "recommendations", "next_actions",
            "security_tips" — ready to merge directly into an orchestrator
            response or JSON API payload.
        """
        return {
            "explanation": self.generate(indicators),
            "recommendations": self.get_recommendations(indicators),
            "next_actions": self.get_next_actions(risk_level),
            "security_tips": self.get_security_tips(),
        }

    # ─────────────────────────────────────────────────────────────────
    # Internal helpers
    # ─────────────────────────────────────────────────────────────────

    @staticmethod
    def _join_fragments(fragments: list[str]) -> str:
        """Join sentence fragments with natural English conjunctions.

        Examples:
            ["a"]              -> "a"
            ["a", "b"]         -> "a and b"
            ["a", "b", "c"]    -> "a, b, and c"
        """
        if len(fragments) == 1:
            return fragments[0]
        if len(fragments) == 2:
            return f"{fragments[0]} and {fragments[1]}"
        return ", ".join(fragments[:-1]) + f", and {fragments[-1]}"

    @staticmethod
    def _closing_statement(ordered_categories: list[str]) -> str:
        """Pick an appropriate closing sentence based on which categories fired."""
        high_severity = {"credential_theft", "authority_impersonation"}
        if any(cat in high_severity for cat in ordered_categories):
            return "These are common techniques used in phishing and social engineering attacks to steal money or personal information."
        return "These patterns are commonly associated with scam or fraudulent messaging."

    @staticmethod
    def _deduplicate(items: list[str]) -> list[str]:
        """Remove duplicate strings while preserving first-seen order."""
        seen: set[str] = set()
        result: list[str] = []
        for item in items:
            if item not in seen:
                seen.add(item)
                result.append(item)
        return result


# ─────────────────────────────────────────────────────────────────────────
# Quick manual smoke test (run this file directly: `python explanation_engine.py`)
# ─────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    engine = ExplanationEngine()

    indicators = ["urgency", "authority_impersonation", "suspicious_url", "credential_theft"]

    print("Explanation:\n", engine.generate(indicators))
    print("\nRecommendations:")
    for rec in engine.get_recommendations(indicators):
        print(" -", rec)

    print("\nNext actions (high risk):")
    for action in engine.get_next_actions("high"):
        print(" -", action)

    print("\nNo-indicator fallback:\n", engine.generate([]))

    print("\nFull payload example:")
    payload = engine.build_full_explanation_payload(indicators, "high")
    for key, value in payload.items():
        print(f"\n[{key}]")
        print(value)
