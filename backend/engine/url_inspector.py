"""
url_inspector.py
═══════════════════════════════════════════════════════════════════════════
Responsible for structural and lexical analysis of URLs to detect phishing
and fraud indicators — independent of any page content. This module never
makes a network request; it inspects the URL string itself, which keeps it
fast, offline-safe, and side-effect-free (important when analyzing
potentially malicious links).

Checks performed
-----------------
1. URL shorteners        — masks the real destination (bit.ly, tinyurl, ...)
2. Suspicious TLDs        — cheap/disposable domains favored by scammers
3. IP-address domains      — raw IPs instead of a registered domain name
4. Excessive subdomains    — e.g. login.secure.sbi.verify-account.xyz
5. Suspicious keywords     — login/verify/secure/update/account/banking, etc.
   used to impersonate legitimate services in the hostname or path
6. Non-standard port       — unusual ports sometimes used to evade filters
7. '@' symbol in URL       — classic technique to disguise the real host
8. Missing HTTPS           — plaintext HTTP on a page asking for credentials
"""

from __future__ import annotations

import ipaddress
import logging
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

from .pattern_library import PatternLibrary, PatternLibraryError

logger = logging.getLogger(__name__)


@dataclass
class URLInspectionResult:
    """Structured result of a single URL inspection.

    Attributes:
        url: The original URL that was inspected.
        is_valid: Whether the URL could be parsed at all.
        flags: Short machine-readable flag codes that were triggered
            (e.g. "suspicious_tld", "ip_based_domain").
        reasons: Human-readable explanations matching each flag, in the
            same order as `flags`.
        risk_points: Cumulative risk contribution from this URL (0-35,
            capped — final clamping to 0-100 happens in RiskScorer).
        domain: The extracted hostname, if parsing succeeded.
    """

    url: str
    is_valid: bool
    flags: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    risk_points: int = 0
    domain: str | None = None

    def to_dict(self) -> dict:
        """Serialize to a plain dict (handy for JSON API responses)."""
        return {
            "url": self.url,
            "is_valid": self.is_valid,
            "flags": self.flags,
            "reasons": self.reasons,
            "risk_points": self.risk_points,
            "domain": self.domain,
        }


class URLInspector:
    """Inspects URLs for structural and lexical phishing indicators.

    Usage:
        >>> inspector = URLInspector()
        >>> result = inspector.inspect("http://sbi-verify-account.xyz/login")
        >>> result.risk_points
        35
        >>> result.flags
        ['suspicious_tld', 'suspicious_keyword']
    """

    # ── Risk point weights for each individual flag ────────────────────
    # These are intentionally smaller than RiskScorer's category weights;
    # URLInspector produces a *sub-score* that RiskScorer folds into its
    # own "Suspicious URL" / "URL Shortener" categories.
    POINTS_SHORTENER: int = 10
    POINTS_SUSPICIOUS_TLD: int = 10
    POINTS_IP_DOMAIN: int = 15
    POINTS_EXCESSIVE_SUBDOMAINS: int = 8
    POINTS_SUSPICIOUS_KEYWORD: int = 7
    POINTS_AT_SYMBOL: int = 12
    POINTS_NON_STANDARD_PORT: int = 5
    POINTS_NO_HTTPS: int = 5

    #: Maximum a single URL inspection can contribute, regardless of how
    #: many individual flags fire. Keeps one URL from single-handedly
    #: maxing out the entire risk score before other signals are weighed.
    MAX_RISK_POINTS: int = 35

    #: Hostname/path keywords commonly used to impersonate login or
    #: account-management flows.
    SUSPICIOUS_KEYWORDS: tuple[str, ...] = (
        "login",
        "verify",
        "secure",
        "update",
        "account",
        "banking",
        "confirm",
        "signin",
        "password",
        "authenticate",
        "wallet",
        "billing",
    )

    #: A hostname with more than this many dot-separated labels (excluding
    #: the TLD) is considered to have "excessive" subdomains.
    MAX_NORMAL_SUBDOMAIN_DEPTH: int = 3

    #: Ports considered "standard" for ordinary web traffic.
    STANDARD_PORTS: tuple[int, ...] = (80, 443)

    def __init__(self, pattern_library: PatternLibrary | None = None) -> None:
        """Initialize the inspector.

        Args:
            pattern_library: Optional shared PatternLibrary instance (reused
                for suspicious-TLD and shortener lookups). If not provided,
                a new one is constructed, loading the bundled JSON pattern
                files.
        """
        self._library = pattern_library or PatternLibrary()

    # ─────────────────────────────────────────────────────────────────
    # Public API
    # ─────────────────────────────────────────────────────────────────

    def inspect(self, url: str) -> URLInspectionResult:
        """Run the full suite of checks against a single URL.

        Args:
            url: The raw URL string to inspect. A scheme (http/https) is
                added automatically if missing, so bare domains like
                "sbi-verify.xyz" are still inspected correctly.

        Returns:
            A URLInspectionResult describing every flag raised and the
            cumulative risk_points (capped at MAX_RISK_POINTS).
        """
        normalized_url = self._normalize(url)
        parsed = urlparse(normalized_url)
        hostname = parsed.hostname

        if not hostname:
            logger.warning("Could not parse hostname from URL: %r", url)
            return URLInspectionResult(
                url=url,
                is_valid=False,
                flags=["unparseable_url"],
                reasons=["The provided text could not be parsed as a valid URL."],
                risk_points=0,
                domain=None,
            )

        flags: list[str] = []
        reasons: list[str] = []
        points = 0

        # 1. URL shortener
        if self._is_shortener(hostname):
            flags.append("url_shortener")
            reasons.append(f"'{hostname}' is a known URL-shortening service, which can hide the real destination.")
            points += self.POINTS_SHORTENER

        # 2. Suspicious TLD
        suspicious_tld = self._find_suspicious_tld(hostname)
        if suspicious_tld:
            flags.append("suspicious_tld")
            reasons.append(f"The domain uses '{suspicious_tld}', a top-level domain frequently abused for scam sites.")
            points += self.POINTS_SUSPICIOUS_TLD

        # 3. IP-address domain
        if self._is_ip_address(hostname):
            flags.append("ip_based_domain")
            reasons.append("The link uses a raw IP address instead of a registered domain name, a common phishing technique.")
            points += self.POINTS_IP_DOMAIN

        # 4. Excessive subdomains
        subdomain_depth = self._subdomain_depth(hostname)
        if subdomain_depth > self.MAX_NORMAL_SUBDOMAIN_DEPTH:
            flags.append("excessive_subdomains")
            reasons.append(
                f"The domain has an unusually deep subdomain chain ({subdomain_depth} levels), "
                f"often used to make a fake URL look legitimate at a glance."
            )
            points += self.POINTS_EXCESSIVE_SUBDOMAINS

        # 5. Suspicious keywords in hostname or path
        matched_keywords = self._find_suspicious_keywords(normalized_url)
        if matched_keywords:
            flags.append("suspicious_keyword")
            reasons.append(
                "The URL contains sensitive-sounding keywords ("
                + ", ".join(matched_keywords)
                + ") often used to impersonate login or account-verification pages."
            )
            points += self.POINTS_SUSPICIOUS_KEYWORD

        # 6. '@' symbol trick (everything before '@' is ignored by browsers)
        if "@" in normalized_url.split("://", 1)[-1]:
            flags.append("at_symbol_obfuscation")
            reasons.append("The URL contains an '@' symbol, a known trick to disguise the true destination domain.")
            points += self.POINTS_AT_SYMBOL

        # 7. Non-standard port
        if parsed.port is not None and parsed.port not in self.STANDARD_PORTS:
            flags.append("non_standard_port")
            reasons.append(f"The URL connects on a non-standard port ({parsed.port}), which is unusual for legitimate sites.")
            points += self.POINTS_NON_STANDARD_PORT

        # 8. Missing HTTPS
        if parsed.scheme != "https":
            flags.append("no_https")
            reasons.append("The link does not use HTTPS, so any data submitted would not be encrypted in transit.")
            points += self.POINTS_NO_HTTPS

        capped_points = min(points, self.MAX_RISK_POINTS)

        return URLInspectionResult(
            url=url,
            is_valid=True,
            flags=flags,
            reasons=reasons,
            risk_points=capped_points,
            domain=hostname,
        )

    # ─────────────────────────────────────────────────────────────────
    # Internal helpers
    # ─────────────────────────────────────────────────────────────────

    @staticmethod
    def _normalize(url: str) -> str:
        """Ensure the URL has a scheme so urlparse extracts hostname correctly."""
        url = url.strip()
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
            url = "http://" + url
        return url

    def _is_shortener(self, hostname: str) -> bool:
        """Check hostname against the known URL-shortener list."""
        try:
            shorteners = self._library.get_keywords("url_shorteners")
        except PatternLibraryError:
            return False
        hostname_lower = hostname.lower()
        return any(hostname_lower == s.lower() or hostname_lower.endswith("." + s.lower()) for s in shorteners)

    def _find_suspicious_tld(self, hostname: str) -> str | None:
        """Return the matching suspicious TLD if the hostname ends with one, else None."""
        try:
            tlds = self._library.get_keywords("suspicious_tlds")
        except PatternLibraryError:
            return None
        hostname_lower = hostname.lower()
        for tld in tlds:
            if hostname_lower.endswith(tld.lower()):
                return tld
        return None

    @staticmethod
    def _is_ip_address(hostname: str) -> bool:
        """Return True if hostname is a literal IPv4 or IPv6 address."""
        # Strip brackets from IPv6 literals like [::1]
        candidate = hostname.strip("[]")
        try:
            ipaddress.ip_address(candidate)
            return True
        except ValueError:
            return False

    @staticmethod
    def _subdomain_depth(hostname: str) -> int:
        """Count dot-separated labels before the registrable domain+TLD.

        This is a simplified heuristic (no public-suffix-list lookup): it
        treats the last two labels as "domain.tld" and counts everything
        before that as subdomain depth. Good enough for flagging obviously
        excessive chains like a.b.c.d.e.example.com.
        """
        labels = hostname.split(".")
        return max(0, len(labels) - 2)

    def _find_suspicious_keywords(self, url: str) -> list[str]:
        """Return which SUSPICIOUS_KEYWORDS appear in the URL (hostname or path)."""
        url_lower = url.lower()
        return [kw for kw in self.SUSPICIOUS_KEYWORDS if kw in url_lower]


# ─────────────────────────────────────────────────────────────────────────
# Quick manual smoke test (run this file directly: `python url_inspector.py`)
# ─────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    inspector = URLInspector()

    test_urls = [
        "http://sbi-secure-login.xyz/verify-account",
        "https://bit.ly/3xK9z",
        "http://192.168.1.50/banking/login",
        "https://accounts.google.com/signin",
        "http://login.secure.update.account.verify-sbi.tk",
        "http://user@phishing-site.com/login",
    ]

    for test_url in test_urls:
        result = inspector.inspect(test_url)
        print(f"\nURL: {test_url}")
        print(f"  Valid: {result.is_valid}  Domain: {result.domain}")
        print(f"  Risk points: {result.risk_points}")
        print(f"  Flags: {result.flags}")
        for reason in result.reasons:
            print(f"    - {reason}")
