"""Shared feature extraction for the phishing/BEC classifier.

Both the training script (`scripts/train_model.py`) and the inference
path (`app/services/ml_scoring.py`) must derive features the exact same
way, or the trained model's learned weights become meaningless at
serving time. This module is the single source of truth for that
mapping: `ParsedEmail` + auth findings + IOC counts -> a fixed-length,
named feature vector.
"""
from __future__ import annotations

from app.services.auth_results import AuthFinding
from app.services.eml_parser import ParsedEmail

FEATURE_NAMES: list[str] = [
    "auth_fail_count",
    "urgency_keyword_count",
    "display_name_mismatch",
    "reply_to_mismatch",
    "url_count_capped",
    "has_raw_ip_link",
    "has_url_shortener",
    "has_low_reputation_tld",
    "has_attachment",
    "subject_has_urgency_word",
]

_URGENCY_TERMS = (
    "urgent", "immediately", "verify your account", "suspended", "act now",
    "confirm your password", "unusual activity", "will be closed",
)
_SUSPICIOUS_TLDS = {"zip", "mov", "xyz", "top", "click", "gq", "tk", "ml", "cf"}
_SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorte.st",
}


def extract_feature_vector(
    parsed: ParsedEmail,
    auth_findings: list[AuthFinding],
    domains: set[str],
    urls: set[str],
) -> list[float]:
    """Returns a feature vector in the exact order of FEATURE_NAMES."""
    from urllib.parse import urlparse
    import ipaddress
    import re

    auth_fail_count = float(sum(1 for f in auth_findings if f.result in ("fail", "softfail")))

    body_text = (parsed.body_text or "") + " " + (parsed.body_html or "")
    body_lower = body_text.lower()
    urgency_hits = float(sum(1 for term in _URGENCY_TERMS if term in body_lower))

    display_mismatch = 0.0
    if parsed.from_display_name and parsed.from_address and parsed.reply_to_address:
        from_domain = parsed.from_address.rsplit("@", 1)[-1].lower()
        reply_domain = parsed.reply_to_address.rsplit("@", 1)[-1].lower()
        if from_domain != reply_domain:
            display_mismatch = 1.0

    reply_to_mismatch = display_mismatch  # same underlying signal for this feature set

    url_count_capped = float(min(len(urls), 5))

    ip_host_re = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
    has_raw_ip_link = 0.0
    has_shortener = 0.0
    for url in urls:
        try:
            host = urlparse(url).netloc.split(":")[0].lower()
        except ValueError:
            continue
        if ip_host_re.match(host):
            has_raw_ip_link = 1.0
        if host in _SHORTENER_DOMAINS:
            has_shortener = 1.0

    has_low_rep_tld = 0.0
    for domain in domains:
        tld = domain.rsplit(".", 1)[-1].lower() if "." in domain else ""
        if tld in _SUSPICIOUS_TLDS:
            has_low_rep_tld = 1.0
            break

    has_attachment = 1.0 if parsed.attachments else 0.0

    subject_lower = (parsed.subject or "").lower()
    subject_urgency = 1.0 if any(term in subject_lower for term in _URGENCY_TERMS) else 0.0

    return [
        auth_fail_count,
        urgency_hits,
        display_mismatch,
        reply_to_mismatch,
        url_count_capped,
        has_raw_ip_link,
        has_shortener,
        has_low_rep_tld,
        has_attachment,
        subject_urgency,
    ]
