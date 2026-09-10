"""Deterministic heuristics over extracted URLs/domains.

Complements (does not replace) external threat-intel reputation lookups.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

from app.services.analysis_engines.header_forensics import Finding
from app.services.ioc_extraction import is_shortened_url

ENGINE_NAME = "url_domain_analysis"

_IP_HOST_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_SUSPICIOUS_TLDS = {"zip", "mov", "xyz", "top", "click", "gq", "tk", "ml", "cf"}
_URGENCY_KEYWORDS = [
    "verify your account", "urgent action required", "account suspended",
    "confirm your password", "click here immediately", "your account will be closed",
    "unusual activity", "update your payment",
]


def _looks_like_credential_harvest_path(url: str) -> bool:
    lowered = url.lower()
    return any(term in lowered for term in ("login", "verify", "secure", "account", "update", "signin"))


def run(urls: set[str], domains: set[str], body_text: str | None, body_html: str | None) -> list[Finding]:
    findings: list[Finding] = []

    for url in urls:
        parsed = urlparse(url)
        host = parsed.netloc.split(":")[0].lower()

        if _IP_HOST_RE.match(host):
            findings.append(
                Finding(
                    engine=ENGINE_NAME,
                    code="URL_USES_RAW_IP",
                    severity="high",
                    confidence=0.75,
                    description=f"Link points directly to an IP address ({host}) rather than a domain, a common evasion technique.",
                    evidence_ref=f"url:{url}",
                )
            )

        if is_shortened_url(url):
            findings.append(
                Finding(
                    engine=ENGINE_NAME,
                    code="URL_SHORTENER_USED",
                    severity="medium",
                    confidence=0.5,
                    description=f"Link uses a URL-shortening service ({host}), obscuring the true destination.",
                    evidence_ref=f"url:{url}",
                )
            )

        if _looks_like_credential_harvest_path(url) and parsed.scheme == "http":
            findings.append(
                Finding(
                    engine=ENGINE_NAME,
                    code="INSECURE_LOGIN_LOOKING_LINK",
                    severity="medium",
                    confidence=0.45,
                    description=f"Link path suggests a login/verification page but is served over plain HTTP: {url}",
                    evidence_ref=f"url:{url}",
                )
            )

    for domain in domains:
        tld = domain.rsplit(".", 1)[-1].lower() if "." in domain else ""
        if tld in _SUSPICIOUS_TLDS:
            findings.append(
                Finding(
                    engine=ENGINE_NAME,
                    code="LOW_REPUTATION_TLD",
                    severity="low",
                    confidence=0.3,
                    description=f"Domain '{domain}' uses a top-level domain ({tld}) frequently abused for phishing/spam.",
                    evidence_ref=f"domain:{domain}",
                )
            )

    combined_text = " ".join(filter(None, [body_text, body_html])).lower()
    matched_keywords = [kw for kw in _URGENCY_KEYWORDS if kw in combined_text]
    if matched_keywords:
        findings.append(
            Finding(
                engine=ENGINE_NAME,
                code="URGENCY_SOCIAL_ENGINEERING_LANGUAGE",
                severity="medium",
                confidence=min(0.4 + 0.1 * len(matched_keywords), 0.8),
                description=(
                    "Message body contains urgency/social-engineering phrasing commonly used "
                    f"in phishing ({len(matched_keywords)} pattern(s) matched)."
                ),
            )
        )

    return findings
