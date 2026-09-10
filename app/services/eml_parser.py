"""RFC 5322 / MIME parsing of .eml files into structured forensic data.

This module never trusts a single header as ground truth about identity.
It extracts everything present, verbatim, and lets downstream analysis
engines (SPF/DKIM/DMARC checker, header-forensics engine, risk fusion)
draw conclusions from the full picture.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from email import policy
from email.message import EmailMessage as StdEmailMessage
from email.parser import BytesParser
from email.utils import getaddresses, parsedate_to_datetime

_RECEIVED_IP_RE = re.compile(r"\[?(?P<ip>(?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]{3,45})\]?")
_RECEIVED_FROM_RE = re.compile(r"from\s+(?P<host>[^\s;()]+)", re.IGNORECASE)
_RECEIVED_BY_RE = re.compile(r"by\s+(?P<host>[^\s;()]+)", re.IGNORECASE)
_RECEIVED_WITH_RE = re.compile(r"with\s+(?P<proto>[A-Za-z0-9/._-]+)", re.IGNORECASE)
_URL_RE = re.compile(r"https?://[^\s\"'<>()\]]+", re.IGNORECASE)


@dataclass
class ParsedHeader:
    sequence: int
    name: str
    value: str


@dataclass
class ParsedHop:
    hop_index: int
    raw_value: str
    from_host: str | None = None
    from_ip: str | None = None
    by_host: str | None = None
    with_protocol: str | None = None
    timestamp: datetime | None = None
    parse_confidence: str = "high"


@dataclass
class ParsedAttachment:
    filename: str | None
    declared_mime_type: str | None
    payload: bytes
    is_archive: bool = False


@dataclass
class ParsedEmail:
    message_id: str | None
    subject: str | None
    date_header: datetime | None
    from_display_name: str | None
    from_address: str | None
    reply_to_address: str | None
    return_path: str | None
    to_addresses: list[str]
    cc_addresses: list[str]
    body_text: str | None
    body_html: str | None
    headers: list[ParsedHeader]
    received_hops: list[ParsedHop]
    attachments: list[ParsedAttachment]
    urls_in_body: list[str] = field(default_factory=list)


_ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".tar", ".gz", ".tgz"}


def parse_received_header(raw_value: str, hop_index: int) -> ParsedHop:
    """Best-effort structured parse of a single Received: header value.

    Received headers are not machine-strict and vary by MTA, so parsing
    failures degrade the confidence rather than raising -- forensic data
    should never be silently dropped.
    """
    hop = ParsedHop(hop_index=hop_index, raw_value=raw_value)
    try:
        from_match = _RECEIVED_FROM_RE.search(raw_value)
        if from_match:
            hop.from_host = from_match.group("host").strip(";,")

        by_match = _RECEIVED_BY_RE.search(raw_value)
        if by_match:
            hop.by_host = by_match.group("host").strip(";,")

        with_match = _RECEIVED_WITH_RE.search(raw_value)
        if with_match:
            hop.with_protocol = with_match.group("proto").strip(";,")

        # Look for an IP specifically within the "from" clause first.
        search_window = raw_value
        if from_match:
            search_window = raw_value[from_match.start():]
        ip_match = _RECEIVED_IP_RE.search(search_window)
        if ip_match:
            hop.from_ip = ip_match.group("ip")

        # The timestamp is after the trailing ';' in a Received header.
        if ";" in raw_value:
            date_part = raw_value.rsplit(";", 1)[-1].strip()
            try:
                hop.timestamp = parsedate_to_datetime(date_part)
            except (TypeError, ValueError):
                hop.parse_confidence = "medium"
        else:
            hop.parse_confidence = "low"

        if not hop.from_host and not hop.from_ip:
            hop.parse_confidence = "low"
    except Exception:
        hop.parse_confidence = "low"
    return hop


def _extract_addresses(msg: StdEmailMessage, header_name: str) -> list[str]:
    raw = msg.get_all(header_name, [])
    return [addr for _, addr in getaddresses(raw) if addr]


def guess_is_archive(filename: str | None) -> bool:
    if not filename:
        return False
    lowered = filename.lower()
    return any(lowered.endswith(ext) for ext in _ARCHIVE_EXTENSIONS)


def parse_eml_bytes(raw_bytes: bytes) -> ParsedEmail:
    """Parses raw .eml bytes into a fully structured ParsedEmail.

    Uses Python's modern `email.policy.default` for RFC 5322 / MIME
    compliant parsing including proper header decoding (RFC 2047).
    """
    msg: StdEmailMessage = BytesParser(policy=policy.default).parsebytes(raw_bytes)

    headers: list[ParsedHeader] = []
    for idx, (name, value) in enumerate(msg.items()):
        headers.append(ParsedHeader(sequence=idx, name=name, value=str(value)))

    received_values = msg.get_all("Received", [])
    hops = [parse_received_header(str(v), idx) for idx, v in enumerate(received_values)]

    from_addresses = getaddresses(msg.get_all("From", []))
    from_display_name, from_address = (from_addresses[0] if from_addresses else (None, None))

    reply_to_list = _extract_addresses(msg, "Reply-To")
    return_path_list = _extract_addresses(msg, "Return-Path")

    date_header = None
    if msg.get("Date"):
        try:
            date_header = parsedate_to_datetime(msg.get("Date"))
        except (TypeError, ValueError):
            date_header = None

    body_text = None
    body_html = None
    attachments: list[ParsedAttachment] = []

    if msg.is_multipart():
        for part in msg.walk():
            content_disposition = part.get_content_disposition()
            content_type = part.get_content_type()

            if content_disposition == "attachment" or (
                content_disposition != "inline" and part.get_filename()
            ):
                payload = part.get_payload(decode=True) or b""
                filename = part.get_filename()
                attachments.append(
                    ParsedAttachment(
                        filename=filename,
                        declared_mime_type=content_type,
                        payload=payload,
                        is_archive=guess_is_archive(filename),
                    )
                )
                continue

            if content_type == "text/plain" and body_text is None:
                body_text = part.get_content()
            elif content_type == "text/html" and body_html is None:
                body_html = part.get_content()
    else:
        content_type = msg.get_content_type()
        if content_type == "text/html":
            body_html = msg.get_content()
        else:
            body_text = msg.get_content()

    urls: set[str] = set()
    for text_blob in (body_text, body_html):
        if text_blob:
            urls.update(_URL_RE.findall(text_blob))

    return ParsedEmail(
        message_id=msg.get("Message-ID"),
        subject=msg.get("Subject"),
        date_header=date_header,
        from_display_name=from_display_name or None,
        from_address=from_address or None,
        reply_to_address=reply_to_list[0] if reply_to_list else None,
        return_path=return_path_list[0] if return_path_list else None,
        to_addresses=_extract_addresses(msg, "To"),
        cc_addresses=_extract_addresses(msg, "Cc"),
        body_text=body_text,
        body_html=body_html,
        headers=headers,
        received_hops=hops,
        attachments=attachments,
        urls_in_body=sorted(urls),
    )
