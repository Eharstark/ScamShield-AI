"""
pattern_library.py
═══════════════════════════════════════════════════════════════════════════
Responsible for loading, caching, and exposing all keyword/pattern sets used
across the ScamShield AI detection engine (urgency, authority impersonation,
financial lures, credential theft, suspicious TLDs, URL shorteners).

Design notes
------------
- Patterns live as flat JSON files in `engine/patterns/` so non-engineers
  (e.g. a hackathon teammate) can extend keyword lists without touching code.
- Matching is case-insensitive and uses simple substring search, which is
  fast, dependency-free, and good enough for an MVP rule-based engine.
- The library loads each file once and caches it in memory — cheap to
  construct, cheap to reuse across many ScamAnalyzer calls.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

logger = logging.getLogger(__name__)


class PatternLibraryError(Exception):
    """Raised when a pattern file is missing, unreadable, or malformed."""


@dataclass(frozen=True)
class PatternMatch:
    """A single keyword hit found inside a piece of text.

    Attributes:
        category: Which pattern set the match came from (e.g. "urgency_keywords").
        keyword: The exact keyword/phrase that matched.
        position: Character offset of the match within the searched text.
    """

    category: str
    keyword: str
    position: int


@dataclass
class PatternSet:
    """In-memory representation of a single loaded pattern JSON file."""

    name: str
    description: str
    keywords: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        # Pre-lowercase once at load time so every lookup is a cheap compare.
        self._lowered: list[str] = [kw.lower() for kw in self.keywords]

    def find_all(self, text_lower: str) -> list[PatternMatch]:
        """Find every occurrence of this set's keywords inside `text_lower`.

        Args:
            text_lower: The *already lowercased* text to search.

        Returns:
            A list of PatternMatch objects, one per occurrence found.
        """
        matches: list[PatternMatch] = []
        for keyword in self._lowered:
            start = 0
            while True:
                idx = text_lower.find(keyword, start)
                if idx == -1:
                    break
                matches.append(PatternMatch(category=self.name, keyword=keyword, position=idx))
                start = idx + len(keyword)
        return matches

    def any_match(self, text_lower: str) -> bool:
        """Fast boolean check — stops at the first hit instead of collecting all."""
        return any(keyword in text_lower for keyword in self._lowered)


class PatternLibrary:
    """Loads JSON-defined keyword sets and provides matching helpers.

    Usage:
        >>> library = PatternLibrary()
        >>> library.find_matches("urgency_keywords", "Your account suspended!")
        [PatternMatch(category='urgency_keywords', keyword='account suspended', position=5)]

    The library is intentionally data-driven: adding a new scam signal is a
    matter of editing/adding a JSON file in `engine/patterns/`, not changing
    Python code.
    """

    #: Filenames expected inside the patterns directory. Keys double as the
    #: canonical "category" name used throughout the rest of the engine.
    DEFAULT_PATTERN_FILES: dict[str, str] = {
        "urgency_keywords": "urgency_keywords.json",
        "authority_names": "authority_names.json",
        "financial_lure": "financial_lure.json",
        "credential_theft": "credential_theft.json",
        "suspicious_tlds": "suspicious_tlds.json",
        "url_shorteners": "url_shorteners.json",
    }

    def __init__(self, patterns_dir: str | Path | None = None) -> None:
        """Initialize the library and eagerly load all known pattern files.

        Args:
            patterns_dir: Directory containing the pattern JSON files.
                Defaults to the `patterns/` folder shipped alongside this module.

        Raises:
            PatternLibraryError: If a required pattern file is missing or invalid.
        """
        self.patterns_dir = Path(patterns_dir) if patterns_dir else Path(__file__).parent / "patterns"
        self._pattern_sets: dict[str, PatternSet] = {}
        self._load_all()

    # ─────────────────────────────────────────────────────────────────
    # Loading
    # ─────────────────────────────────────────────────────────────────

    def _load_all(self) -> None:
        """Load every file listed in DEFAULT_PATTERN_FILES into memory."""
        for category, filename in self.DEFAULT_PATTERN_FILES.items():
            self._pattern_sets[category] = self._load_file(category, filename)
        logger.info("PatternLibrary loaded %d pattern sets from %s", len(self._pattern_sets), self.patterns_dir)

    def _load_file(self, category: str, filename: str) -> PatternSet:
        """Read and parse a single pattern JSON file.

        Args:
            category: Logical name for this pattern set (used as dict key).
            filename: JSON filename relative to `self.patterns_dir`.

        Returns:
            A populated PatternSet.

        Raises:
            PatternLibraryError: If the file is missing or malformed.
        """
        file_path = self.patterns_dir / filename
        if not file_path.exists():
            raise PatternLibraryError(
                f"Pattern file not found: {file_path}. "
                f"Expected a JSON file with 'description' and 'keywords' fields."
            )

        try:
            with file_path.open("r", encoding="utf-8") as f:
                raw = json.load(f)
        except json.JSONDecodeError as exc:
            raise PatternLibraryError(f"Malformed JSON in {file_path}: {exc}") from exc
        except OSError as exc:
            raise PatternLibraryError(f"Could not read {file_path}: {exc}") from exc

        keywords = raw.get("keywords", [])
        if not isinstance(keywords, list) or not all(isinstance(k, str) for k in keywords):
            raise PatternLibraryError(f"{file_path} must contain a 'keywords' list of strings.")

        return PatternSet(
            name=category,
            description=raw.get("description", ""),
            keywords=keywords,
        )

    def reload(self) -> None:
        """Re-read all pattern files from disk.

        Useful in long-running processes (e.g. a Flask server) where someone
        edits a JSON pattern file and wants changes picked up without a restart.
        """
        self._pattern_sets.clear()
        self._load_all()

    # ─────────────────────────────────────────────────────────────────
    # Querying
    # ─────────────────────────────────────────────────────────────────

    def categories(self) -> list[str]:
        """Return the list of loaded pattern category names."""
        return list(self._pattern_sets.keys())

    def get_keywords(self, category: str) -> list[str]:
        """Return the raw keyword list for a given category.

        Args:
            category: One of `self.categories()`.

        Raises:
            PatternLibraryError: If the category does not exist.
        """
        pattern_set = self._get_set(category)
        return list(pattern_set.keywords)

    def find_matches(self, category: str, text: str) -> list[PatternMatch]:
        """Find all matches of a single category's keywords within `text`.

        Args:
            category: Which pattern set to search with (e.g. "urgency_keywords").
            text: The raw text to search (any casing).

        Returns:
            List of PatternMatch hits, possibly empty.

        Raises:
            PatternLibraryError: If the category does not exist.
        """
        pattern_set = self._get_set(category)
        return pattern_set.find_all(text.lower())

    def find_all_matches(self, text: str, categories: Iterable[str] | None = None) -> dict[str, list[PatternMatch]]:
        """Run matching across multiple (or all) categories at once.

        Args:
            text: The raw text to search.
            categories: Optional subset of categories to check. Defaults to all loaded categories.

        Returns:
            Mapping of category -> list of PatternMatch (categories with zero
            hits are included with an empty list, so callers can rely on all
            requested keys being present).
        """
        text_lower = text.lower()
        target_categories = list(categories) if categories is not None else self.categories()

        results: dict[str, list[PatternMatch]] = {}
        for category in target_categories:
            pattern_set = self._get_set(category)
            results[category] = pattern_set.find_all(text_lower)
        return results

    def has_match(self, category: str, text: str) -> bool:
        """Cheap boolean check: does `text` contain any keyword from `category`?"""
        pattern_set = self._get_set(category)
        return pattern_set.any_match(text.lower())

    def count_matches(self, category: str, text: str) -> int:
        """Return how many keyword occurrences from `category` appear in `text`."""
        return len(self.find_matches(category, text))

    # ─────────────────────────────────────────────────────────────────
    # Internal helpers
    # ─────────────────────────────────────────────────────────────────

    def _get_set(self, category: str) -> PatternSet:
        """Look up a loaded PatternSet, raising a clear error if missing."""
        pattern_set = self._pattern_sets.get(category)
        if pattern_set is None:
            raise PatternLibraryError(
                f"Unknown pattern category: '{category}'. "
                f"Available categories: {', '.join(self.categories())}"
            )
        return pattern_set


# ─────────────────────────────────────────────────────────────────────────
# Quick manual smoke test (run this file directly: `python pattern_library.py`)
# ─────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    library = PatternLibrary()
    print("Loaded categories:", library.categories())

    sample_sms = (
        "Dear customer, your SBI account suspended due to KYC update required. "
        "Click immediately to verify your identity and claim your cashback reward. "
        "Visit http://sbi-verify.xyz now."
    )

    all_matches = library.find_all_matches(sample_sms)
    for category, matches in all_matches.items():
        if matches:
            print(f"\n[{category}] {len(matches)} match(es):")
            for m in matches:
                print(f"  - '{m.keyword}' at position {m.position}")
