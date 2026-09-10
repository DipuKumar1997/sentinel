"""Tests for sending the analysis report back to whoever forwarded the
suspicious email (app/services/email_notification.py), wired into the
mailbox-polling pipeline.

Real SMTP is mocked throughout -- these tests verify OUR wiring logic
(recipient extraction from the forwarding envelope, not the claimed
original sender; graceful failure handling; Note creation) rather than
actual network delivery, which cannot be exercised in this environment.
"""
from unittest.mock import MagicMock, patch

import pytest

from app.services.email_notification import NotificationResult, _extract_reply_address, _guess_smtp_host


# ---------------------------------------------------------------------
# Pure unit tests
# ---------------------------------------------------------------------

def test_extract_reply_address_from_display_name_format():
    assert _extract_reply_address('"Sam Employee" <sam95074450@gmail.com>') == "sam95074450@gmail.com"


def test_extract_reply_address_from_bare_address():
    assert _extract_reply_address("sam95074450@gmail.com") == "sam95074450@gmail.com"


def test_extract_reply_address_none_when_missing():
    assert _extract_reply_address(None) is None
    assert _extract_reply_address("") is None


def test_guess_smtp_host_swaps_imap_for_smtp():
    assert _guess_smtp_host("imap.gmail.com") == "smtp.gmail.com"


def test_guess_smtp_host_falls_back_when_no_imap_substring():
    assert _guess_smtp_host("mail.example.com") == "mail.example.com"


def test_guess_smtp_host_none_when_no_host():
    assert _guess_smtp_host(None) is None


# ---------------------------------------------------------------------
# Full mailbox-polling integration, with SMTP mocked
# ---------------------------------------------------------------------

async def _register_admin_and_mailbox(client):
    r = await client.post(
        "/api/v1/auth/register",
        json={"full_name": "Admin", "email": "admin@acmecorp.com", "password": "SuperSecret123!", "organization_name": "Acme Corp"},
    )
    token = r.json()["message"].split("verification_token=")[-1]
    await client.post("/api/v1/auth/verify-email", json={"token": token})
    r = await client.post("/api/v1/auth/login", json={"email": "admin@acmecorp.com", "password": "SuperSecret123!"})
    headers = {"Authorization": f"Bearer {r.json()['access_token']}"}

    r = await client.post(
        "/api/v1/mailboxes", headers=headers,
        json={
            "address": "security@acmecorp.com", "imap_host": "imap.gmail.com",
            "imap_username": "security@acmecorp.com", "imap_password": "fake-app-password",
        },
    )
    return headers, r.json()["id"]


def _forwarded_eml(from_addr: str) -> bytes:
    return (
        f"From: {from_addr}\r\n"
        "To: security@acmecorp.com\r\n"
        "Subject: Fwd: suspicious email\r\n"
        "Message-ID: <outer@acmecorp.com>\r\n"
        "Content-Type: text/plain\r\n\r\n"
        "Please check this out.\r\n"
    ).encode()


class _FakeIMAPForNotify:
    def __init__(self, messages):
        self.messages = messages
        self.seen_flags = set()

    def status(self, folder, what):
        return "OK", [f"{folder} (UIDVALIDITY 1 UIDNEXT {max(self.messages, default=0) + 1})".encode()]

    def select(self, folder, readonly=False):
        return "OK", [b"1"]

    def uid(self, command, *args):
        import re
        if command == "search":
            match = re.search(r"UID (\d+):\*", args[-1])
            start = int(match.group(1)) if match else 1
            matching = sorted(u for u in self.messages if u >= start)
            return "OK", [" ".join(str(u) for u in matching).encode()]
        if command == "fetch":
            uid = int(args[0])
            return ("OK", [(b"1 (RFC822 {n})", self.messages[uid])]) if uid in self.messages else ("OK", [None])
        if command == "store":
            self.seen_flags.add(int(args[0]))
            return "OK", [b"OK"]

    def logout(self):
        pass


@pytest.mark.asyncio
async def test_notification_sent_to_forwarding_employee_not_claimed_sender(client):
    """The email must go to the person who forwarded it (outer From),
    never to an address claimed inside the forwarded content.
    """
    headers, mailbox_id = await _register_admin_and_mailbox(client)
    eml = _forwarded_eml("sam95074450@gmail.com")

    with patch("app.services.mailbox_polling._connect", lambda mb: _FakeIMAPForNotify({1: eml})), \
         patch("app.services.mailbox_polling.email_notification.send_report_notification") as mock_send:
        mock_send.return_value = NotificationResult(sent=True, recipient="sam95074450@gmail.com")
        r = await client.post(f"/api/v1/mailboxes/{mailbox_id}/poll-now", headers=headers)

    assert r.status_code == 200
    assert r.json()["outcomes"][0]["status"] == "created"
    mock_send.assert_called_once()
    call_kwargs = mock_send.call_args.kwargs
    assert call_kwargs["to_header_value"] == "sam95074450@gmail.com"
    assert "html_report" in call_kwargs
    assert isinstance(call_kwargs["pdf_report"], bytes)
    assert call_kwargs["pdf_report"][:4] == b"%PDF"


@pytest.mark.asyncio
async def test_notification_failure_does_not_undo_case_creation(client):
    """If SMTP sending fails (bad creds, network issue), the case must
    still exist -- only the notification attempt fails.
    """
    headers, mailbox_id = await _register_admin_and_mailbox(client)
    eml = _forwarded_eml("sam95074450@gmail.com")

    with patch("app.services.mailbox_polling._connect", lambda mb: _FakeIMAPForNotify({1: eml})), \
         patch("app.services.mailbox_polling.email_notification.send_report_notification") as mock_send:
        mock_send.return_value = NotificationResult(sent=False, recipient="sam95074450@gmail.com", error_detail="SMTP auth failed")
        r = await client.post(f"/api/v1/mailboxes/{mailbox_id}/poll-now", headers=headers)

    assert r.status_code == 200
    outcome = r.json()["outcomes"][0]
    assert outcome["status"] == "created"  # case creation unaffected by notification failure
    case_id = outcome["case_id"]

    r = await client.get(f"/api/v1/cases/{case_id}", headers=headers)
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_no_notification_attempted_when_no_forwarding_address_found(client):
    """A message with no discoverable outer From must not crash the
    pipeline -- notification is simply skipped.
    """
    headers, mailbox_id = await _register_admin_and_mailbox(client)
    eml = (
        "To: security@acmecorp.com\r\nSubject: no from header\r\n"
        "Content-Type: text/plain\r\n\r\nbody\r\n"
    ).encode()

    with patch("app.services.mailbox_polling._connect", lambda mb: _FakeIMAPForNotify({1: eml})), \
         patch("app.services.mailbox_polling.email_notification.send_report_notification") as mock_send:
        r = await client.post(f"/api/v1/mailboxes/{mailbox_id}/poll-now", headers=headers)

    assert r.status_code == 200
    assert r.json()["outcomes"][0]["status"] == "created"
    mock_send.assert_not_called()


@pytest.mark.no_autouse_smtp_mock
def test_send_report_notification_uses_smtp_starttls(monkeypatch):
    """Verifies the actual SMTP call sequence (STARTTLS, login,
    send_message) without touching a real network -- mocks smtplib.SMTP
    itself rather than our own wrapper, so this test would catch a
    regression in how we drive the smtplib API.
    """
    from app.models.case import Mailbox
    from app.services import email_notification

    mailbox = Mailbox(
        address="security@acmecorp.com",
        imap_host="imap.gmail.com",
        imap_username="security@acmecorp.com",
        encrypted_password="irrelevant",
        smtp_host=None,
        smtp_port=587,
        smtp_use_tls=True,
        notify_reporter=True,
    )

    fake_server = MagicMock()
    fake_smtp_cls = MagicMock()
    fake_smtp_cls.return_value.__enter__.return_value = fake_server

    with patch("app.services.email_notification.get_decrypted_password", return_value="app-password"), \
         patch("app.services.email_notification.smtplib.SMTP", fake_smtp_cls):
        result = email_notification.send_report_notification(
            mailbox,
            to_header_value="sam95074450@gmail.com",
            case_number="SM-20260908-ABCD1234",
            risk_score=90,
            classification="malicious",
            html_report="<html>report</html>",
            pdf_report=b"%PDF-fake",
        )

    assert result.sent is True
    assert result.recipient == "sam95074450@gmail.com"
    fake_smtp_cls.assert_called_once_with("smtp.gmail.com", 587, timeout=15)
    fake_server.starttls.assert_called_once()
    fake_server.login.assert_called_once_with("security@acmecorp.com", "app-password")
    fake_server.send_message.assert_called_once()
