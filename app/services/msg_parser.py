"""Outlook .msg file parsing.

Converts a proprietary Outlook MSG (OLE compound file) into the exact
same `ParsedEmail` dataclass produced by `app.services.eml_parser`, so
every downstream step (IOC extraction, analysis engines, risk fusion)
needs zero awareness of which format the evidence originally arrived in.

Limitation, stated plainly: `.msg` files do not always carry a full,
standards-compliant `Received:` header chain the way `.eml` does --
Outlook sometimes stores routing information in proprietary properties
instead. Where headers are unavailable, hops/attachments are still
extracted from whatever `extract_msg` exposes, but `parse_confidence`
is set conservatively low rather than fabricated.
"""
from __future__ import annotations

import io
import re
from email.utils import getaddresses, parsedate_to_datetime

import extract_msg

from app.services.eml_parser import (
    ParsedAttachment,
    ParsedEmail,
    ParsedHeader,
    guess_is_archive,
    parse_received_header,
)

_URL_RE = re.compile(r"https?://[^\s\"'<>()\]]+", re.IGNORECASE)


def parse_msg_bytes(raw_bytes: bytes) -> ParsedEmail:
    msg = extract_msg.Message(io.BytesIO(raw_bytes))
    try:
        header_text = msg.header if isinstance(msg.header, str) else ""

        headers: list[ParsedHeader] = []
        received_values: list[str] = []
        if header_text:
            for idx, line in enumerate(header_text.splitlines()):
                if ":" not in line:
                    continue
                name, _, value = line.partition(":")
                name, value = name.strip(), value.strip()
                if not name:
                    continue
                headers.append(ParsedHeader(sequence=idx, name=name, value=value))
                if name.lower() == "received":
                    received_values.append(value)

        hops = [parse_received_header(v, idx) for idx, v in enumerate(received_values)]

        from_address = (msg.sender_email or "").strip() or None
        from_display_name = (msg.sender_name or "").strip() or None
        if from_address and "@" not in from_address and msg.sender:
            # Fall back to parsing the combined "Display Name <addr>" form.
            parsed_pairs = getaddresses([msg.sender])
            if parsed_pairs:
                from_display_name, from_address = parsed_pairs[0]

        to_addresses = [addr for _, addr in getaddresses([msg.to or ""]) if addr]
        cc_addresses = [addr for _, addr in getaddresses([msg.cc or ""]) if addr]

        reply_to_header = next((h.value for h in headers if h.name.lower() == "reply-to"), None)
        reply_to_address = None
        if reply_to_header:
            pairs = getaddresses([reply_to_header])
            reply_to_address = pairs[0][1] if pairs else None

        return_path_header = next((h.value for h in headers if h.name.lower() == "return-path"), None)
        return_path = None
        if return_path_header:
            pairs = getaddresses([return_path_header])
            return_path = pairs[0][1] if pairs else return_path_header.strip("<>")

        date_header = None
        raw_date = msg.date
        if raw_date:
            try:
                date_header = parsedate_to_datetime(str(raw_date)) if isinstance(raw_date, str) else raw_date
            except (TypeError, ValueError):
                date_header = None

        body_text = msg.body or None
        body_html = getattr(msg, "htmlBody", None)
        if isinstance(body_html, bytes):
            body_html = body_html.decode(errors="replace")

        attachments: list[ParsedAttachment] = []
        for att in msg.attachments:
            try:
                filename = att.longFilename or att.shortFilename or "attachment"
                payload = att.data if isinstance(att.data, bytes) else bytes(att.data or b"")
                attachments.append(
                    ParsedAttachment(
                        filename=filename,
                        declared_mime_type=None,
                        payload=payload,
                        is_archive=guess_is_archive(filename),
                    )
                )
            except Exception:
                # A single malformed attachment must not fail the whole
                # ingestion -- it is skipped, not silently substituted.
                continue

        urls: set[str] = set()
        for blob in (body_text, body_html):
            if blob:
                urls.update(_URL_RE.findall(blob))

        message_id = next((h.value for h in headers if h.name.lower() == "message-id"), None)
        subject = msg.subject or None

        return ParsedEmail(
            message_id=message_id,
            subject=subject,
            date_header=date_header,
            from_display_name=from_display_name,
            from_address=from_address,
            reply_to_address=reply_to_address,
            return_path=return_path,
            to_addresses=to_addresses,
            cc_addresses=cc_addresses,
            body_text=body_text,
            body_html=body_html,
            headers=headers,
            received_hops=hops,
            attachments=attachments,
            urls_in_body=sorted(urls),
        )
    finally:
        msg.close()
