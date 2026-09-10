"""Extracts and normalizes indicators of compromise (IOCs) from a parsed
email: domains, IPs, URLs, and attachment hashes.

This module is purely extraction/normalization. Reputation enrichment
(threat intel lookups) happens in `app.services.threat_intel`.
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlparse

from app.services.eml_parser import ParsedAttachment, ParsedEmail, ParsedHop

_SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorte.st",
}


@dataclass
class ExtractedIOCs:
    domains: set[str]
    ips: set[str]
    urls: set[str]
    attachment_hashes: dict[str, bytes]  # sha256 -> payload (payload kept only transiently)


def _domain_from_address(address: str | None) -> str | None:
    if not address or "@" not in address:
        return None
    return address.rsplit("@", 1)[-1].lower().strip()


def _is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def normalize_url(url: str) -> str:
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    path = parsed.path or "/"
    return f"{scheme}://{netloc}{path}"


def is_shortened_url(url: str) -> bool:
    try:
        netloc = urlparse(url).netloc.lower()
        return netloc in _SHORTENER_DOMAINS
    except ValueError:
        return False


def extract_iocs(parsed: ParsedEmail) -> ExtractedIOCs:
    domains: set[str] = set()
    ips: set[str] = set()
    urls: set[str] = set(parsed.urls_in_body)

    for candidate in (parsed.from_address, parsed.reply_to_address, parsed.return_path):
        d = _domain_from_address(candidate)
        if d:
            domains.add(d)

    for addr in [*parsed.to_addresses, *parsed.cc_addresses]:
        d = _domain_from_address(addr)
        if d:
            domains.add(d)

    for hop in parsed.received_hops:
        if hop.from_ip and _is_valid_ip(hop.from_ip):
            ips.add(hop.from_ip)
        if hop.from_host and not _is_valid_ip(hop.from_host):
            domains.add(hop.from_host.lower())

    for url in urls:
        try:
            netloc = urlparse(url).netloc.split(":")[0].lower()
            if netloc:
                if _is_valid_ip(netloc):
                    ips.add(netloc)
                else:
                    domains.add(netloc)
        except ValueError:
            continue

    attachment_hashes: dict[str, bytes] = {}
    for att in parsed.attachments:
        digest = hashlib.sha256(att.payload).hexdigest()
        attachment_hashes[digest] = att.payload

    return ExtractedIOCs(domains=domains, ips=ips, urls=urls, attachment_hashes=attachment_hashes)


def detect_display_name_mismatch(display_name: str | None, address: str | None) -> bool:
    """Flags a classic BEC/spoofing signal: display name implies one
    person/brand while the actual address domain doesn't match at all.
    Heuristic only -- a low-cost, high-value signal, not a verdict.
    """
    if not display_name or not address:
        return False
    domain = _domain_from_address(address) or ""
    display_lower = display_name.lower()
    # If the display name contains a well-known free-mail brand string but
    # the actual domain isn't that brand, that's suspicious.
    brand_hints = ["paypal", "microsoft", "apple", "amazon", "bank", "google", "irs", "hr department"]
    for brand in brand_hints:
        if brand in display_lower and brand.replace(" ", "") not in domain:
            return True
    return False
