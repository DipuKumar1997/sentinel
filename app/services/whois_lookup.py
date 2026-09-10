"""Domain WHOIS/registration intelligence.

Raw WHOIS (TCP port 43) is queried directly via a socket rather than a
paid API, since registration date/registrar/nameservers are still
served for free by the registry's own WHOIS server for most TLDs. This
is inherently best-effort: some networks block port 43 outbound,
response formats vary wildly by registry/registrar, and some registrars
redact data behind privacy protection -- all of which this module
handles by returning "unavailable" rather than fabricating a plausible
value. Never invent a registration date, registrar name, or age that
wasn't actually parsed from a real response.
"""
from __future__ import annotations

import re
import socket
from dataclasses import dataclass
from datetime import datetime, timezone

_WHOIS_TIMEOUT = 6.0
_IANA_WHOIS_HOST = "whois.iana.org"

# Known per-TLD WHOIS servers for the most common TLDs, to avoid an
# extra round trip through IANA's referral WHOIS for the common case.
# Falls back to querying IANA for anything not listed here.
_KNOWN_WHOIS_SERVERS = {
    "com": "whois.verisign-grs.com",
    "net": "whois.verisign-grs.com",
    "org": "whois.pir.org",
    "info": "whois.afilias.net",
    "io": "whois.nic.io",
    "co": "whois.nic.co",
    "dev": "whois.nic.google",
    "app": "whois.nic.google",
}

_CREATION_DATE_RE = re.compile(
    r"(?:creation date|created on|registered on|domain registration date)\s*:\s*(.+)", re.IGNORECASE
)
_REGISTRAR_RE = re.compile(r"registrar\s*:\s*(.+)", re.IGNORECASE)
_NAMESERVER_RE = re.compile(r"name server\s*:\s*(.+)", re.IGNORECASE)


@dataclass
class WhoisResult:
    domain: str
    available: bool
    registrar: str | None = None
    creation_date: datetime | None = None
    age_days: int | None = None
    nameservers: list[str] | None = None
    error_detail: str | None = None
    source: str = "whois"


def _query_whois_server(host: str, query: str) -> str:
    with socket.create_connection((host, 43), timeout=_WHOIS_TIMEOUT) as sock:
        sock.sendall((query + "\r\n").encode())
        chunks = []
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks).decode(errors="replace")


def _parse_creation_date(text: str) -> datetime | None:
    match = _CREATION_DATE_RE.search(text)
    if not match:
        return None
    raw = match.group(1).strip()
    # WHOIS creation-date formats vary widely; try the most common ones
    # before giving up (returning None, not a guess).
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d", "%d-%b-%Y", "%Y-%m-%dT%H:%M:%S.%f%z", "%Y.%m.%d"):
        try:
            parsed = datetime.strptime(raw, fmt)
            return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed
        except ValueError:
            continue
    return None


def lookup_domain_whois(domain: str) -> WhoisResult:
    tld = domain.rsplit(".", 1)[-1].lower() if "." in domain else ""
    host = _KNOWN_WHOIS_SERVERS.get(tld, _IANA_WHOIS_HOST)

    try:
        raw_text = _query_whois_server(host, domain)
    except (OSError, socket.timeout) as exc:
        return WhoisResult(
            domain=domain, available=False,
            error_detail=f"WHOIS query to {host} failed: {exc}",
        )

    if not raw_text.strip():
        return WhoisResult(domain=domain, available=False, error_detail="Empty WHOIS response.")

    registrar_match = _REGISTRAR_RE.search(raw_text)
    nameservers = sorted({m.strip() for m in _NAMESERVER_RE.findall(raw_text)}) or None
    creation_date = _parse_creation_date(raw_text)

    age_days = None
    if creation_date:
        now = datetime.now(timezone.utc)
        cd = creation_date if creation_date.tzinfo else creation_date.replace(tzinfo=timezone.utc)
        age_days = (now - cd).days

    return WhoisResult(
        domain=domain,
        available=True,
        registrar=registrar_match.group(1).strip() if registrar_match else None,
        creation_date=creation_date,
        age_days=age_days,
        nameservers=nameservers,
    )
