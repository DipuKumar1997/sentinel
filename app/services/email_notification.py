"""Sends the analysis report back to whoever forwarded the suspicious
email, over SMTP.

Reuses the SAME encrypted credential as IMAP receiving
(app/services/mailbox_service.py::get_decrypted_password) -- for Gmail
and most providers, one App Password authenticates both IMAP and SMTP
on the same account, so nothing new needs to be stored. Only the
host/port/TLS settings differ between the two protocols, which is why
`Mailbox.smtp_host`/`smtp_port`/`smtp_use_tls` exist as separate fields
from the IMAP ones.

Sends to the FORWARDING EMPLOYEE's address (the outer envelope's From),
never to any address claimed inside the forwarded content -- this is
the same reporter/sender identity separation enforced everywhere else
in this codebase (see docs/architecture.md section 3).
"""
from __future__ import annotations

import logging
import smtplib
from dataclasses import dataclass
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import getaddresses

from app.models.case import Mailbox
from app.services.mailbox_service import MailboxError, get_decrypted_password

logger = logging.getLogger(__name__)


@dataclass
class NotificationResult:
    sent: bool
    recipient: str | None
    error_detail: str | None = None


def _guess_smtp_host(imap_host: str | None) -> str | None:
    """Best-effort default: most providers name their SMTP host the same
    way as IMAP but with 'imap' swapped for 'smtp' (imap.gmail.com ->
    smtp.gmail.com). Used only when smtp_host wasn't explicitly set.
    """
    if not imap_host:
        return None
    if "imap" in imap_host:
        return imap_host.replace("imap", "smtp", 1)
    return imap_host


def _extract_reply_address(outer_from: str | None) -> str | None:
    """`outer_from` is a raw header value like '"Sam" <sam@x.com>' --
    extract just the address part.
    """
    if not outer_from:
        return None
    pairs = getaddresses([outer_from])
    return pairs[0][1] if pairs and pairs[0][1] else None


def send_report_notification(
    mailbox: Mailbox,
    *,
    to_header_value: str | None,
    case_number: str,
    risk_score: int,
    classification: str,
    html_report: str,
    pdf_report: bytes,
) -> NotificationResult:
    recipient = _extract_reply_address(to_header_value)
    if not recipient:
        return NotificationResult(sent=False, recipient=None, error_detail="No forwarding sender address to reply to.")

    if not mailbox.notify_reporter:
        return NotificationResult(sent=False, recipient=recipient, error_detail="Notifications disabled for this mailbox.")

    smtp_host = mailbox.smtp_host or _guess_smtp_host(mailbox.imap_host)
    if not smtp_host or not mailbox.imap_username:
        return NotificationResult(sent=False, recipient=recipient, error_detail="No SMTP host/credentials configured.")

    try:
        password = get_decrypted_password(mailbox)
    except MailboxError as exc:
        return NotificationResult(sent=False, recipient=recipient, error_detail=f"Could not decrypt credentials: {exc}")

    msg = MIMEMultipart("mixed")
    msg["Subject"] = f"SentinelMail Analysis \u2014 Case {case_number} \u2014 {classification.upper()} ({risk_score}/100)"
    msg["From"] = mailbox.imap_username
    msg["To"] = recipient

    body_alt = MIMEMultipart("alternative")
    body_alt.attach(MIMEText(
        f"Your forwarded email has been analyzed.\n\n"
        f"Case: {case_number}\n"
        f"Risk score: {risk_score}/100\n"
        f"Classification: {classification}\n\n"
        f"The full forensic report is attached (HTML view inline below, PDF attached).\n\n"
        f"This is an automated message from SentinelMail AI.",
        "plain",
    ))
    body_alt.attach(MIMEText(html_report, "html"))
    msg.attach(body_alt)

    pdf_part = MIMEApplication(pdf_report, _subtype="pdf")
    pdf_part.add_header("Content-Disposition", "attachment", filename=f"{case_number}_report.pdf")
    msg.attach(pdf_part)

    try:
        if mailbox.smtp_use_tls:
            with smtplib.SMTP(smtp_host, mailbox.smtp_port, timeout=15) as server:
                server.starttls()
                server.login(mailbox.imap_username, password)
                server.send_message(msg)
        else:
            with smtplib.SMTP_SSL(smtp_host, mailbox.smtp_port, timeout=15) as server:
                server.login(mailbox.imap_username, password)
                server.send_message(msg)
    except (smtplib.SMTPException, OSError) as exc:
        logger.exception("Failed to send report notification for case %s", case_number)
        return NotificationResult(sent=False, recipient=recipient, error_detail=str(exc))

    return NotificationResult(sent=True, recipient=recipient)
