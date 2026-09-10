"""SPF / DKIM / DMARC evidence extraction.

Two sources are used, and both are recorded:
1. `header` -- parsing the Authentication-Results header already added by
   the recipient's receiving MTA (fast, no network calls, but only as
   trustworthy as that upstream MTA).
2. `live_check` -- an optional live DNS-based SPF/DMARC re-check performed
   with dnspython against the claimed sending domain, useful when no
   Authentication-Results header is present or it is not trusted.

Limitations (documented, not hidden): DKIM signature *cryptographic*
verification requires the message body bytes and the signer's public key
and is not attempted here in the prototype -- we surface the DKIM=pass/
fail verdict from Authentication-Results when present, and otherwise
report "unavailable" rather than fabricating a result.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

import dns.exception
import dns.resolver

_AUTH_RESULTS_TOKEN_RE = re.compile(
    r"(?P<mechanism>spf|dkim|dmarc)=(?P<result>[a-zA-Z]+)"
    r"(?:\s+\([^)]*\))?"
    r"(?:\s+(?:smtp\.mailfrom|header\.from|header\.d|header\.i)=(?P<domain>[^\s;]+))?",
    re.IGNORECASE,
)


@dataclass
class AuthFinding:
    mechanism: str  # spf|dkim|dmarc
    result: str  # pass|fail|softfail|neutral|none|temperror|permerror|unavailable
    domain: str | None
    raw_detail: str | None
    source: str  # header|live_check


def parse_authentication_results_header(header_values: list[str]) -> list[AuthFinding]:
    """Parses one or more Authentication-Results header values."""
    findings: list[AuthFinding] = []
    seen_mechanisms: set[str] = set()
    for raw in header_values:
        for match in _AUTH_RESULTS_TOKEN_RE.finditer(raw):
            mechanism = match.group("mechanism").lower()
            if mechanism in seen_mechanisms:
                continue
            seen_mechanisms.add(mechanism)
            findings.append(
                AuthFinding(
                    mechanism=mechanism,
                    result=match.group("result").lower(),
                    domain=match.group("domain"),
                    raw_detail=raw,
                    source="header",
                )
            )
    return findings


def live_check_spf(domain: str, sender_ip: str | None) -> AuthFinding:
    """Best-effort live SPF TXT record lookup.

    Does NOT implement full RFC 7208 SPF macro/include evaluation (that
    requires walking nested includes/redirects against the connecting
    IP). It reports whether an SPF policy exists and its raw mechanism
    set, clearly labeled, so an analyst can evaluate manually if the
    header-based result is absent or distrusted.
    """
    try:
        answers = dns.resolver.resolve(domain, "TXT", lifetime=5.0)
        spf_records = [
            b"".join(chunk for chunk in rdata.strings).decode(errors="replace")
            for rdata in answers
            if any(s.startswith(b"v=spf1") for s in rdata.strings)
        ]
        if not spf_records:
            return AuthFinding("spf", "none", domain, "No SPF TXT record found", "live_check")
        return AuthFinding(
            "spf", "neutral", domain, f"SPF record present: {spf_records[0]}", "live_check"
        )
    except dns.resolver.NXDOMAIN:
        return AuthFinding("spf", "permerror", domain, "Domain does not exist", "live_check")
    except (dns.resolver.NoAnswer, dns.exception.DNSException) as exc:
        return AuthFinding("spf", "temperror", domain, f"DNS lookup issue: {exc}", "live_check")


def live_check_dmarc(domain: str) -> AuthFinding:
    """Looks up _dmarc.<domain> TXT record and reports its policy, without
    asserting alignment (that requires the full DKIM/SPF identifier
    alignment evaluated against the org domain, out of scope for v0.1).
    """
    lookup_domain = f"_dmarc.{domain}"
    try:
        answers = dns.resolver.resolve(lookup_domain, "TXT", lifetime=5.0)
        for rdata in answers:
            txt = b"".join(chunk for chunk in rdata.strings).decode(errors="replace")
            if txt.startswith("v=DMARC1"):
                return AuthFinding("dmarc", "neutral", domain, f"DMARC record present: {txt}", "live_check")
        return AuthFinding("dmarc", "none", domain, "No DMARC record found", "live_check")
    except dns.resolver.NXDOMAIN:
        return AuthFinding("dmarc", "none", domain, "No DMARC record found (NXDOMAIN)", "live_check")
    except (dns.resolver.NoAnswer, dns.exception.DNSException) as exc:
        return AuthFinding("dmarc", "temperror", domain, f"DNS lookup issue: {exc}", "live_check")
