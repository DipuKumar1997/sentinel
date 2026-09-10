"""Tests for IMAP mailbox-forwarding ingestion.

A real IMAP server isn't available in this environment, so
`app.services.mailbox_polling._connect` is mocked with a small fake
IMAP4-like object that mimics exactly the subset of the protocol our
code uses (`status`, `select`, `uid('search', ...)`,
`uid('fetch', ...)`, `uid('store', ...)`, `logout`). This tests our own
polling/dedup/forward-detection logic thoroughly without depending on
`imaplib`'s actual network behavior.
"""
from unittest.mock import patch

import pytest

from app.services import mailbox_polling, mailbox_service


class FakeIMAP:
    """Mimics imaplib.IMAP4 just enough for mailbox_polling.py to work
    against, backed by an in-memory dict of {uid: raw_bytes}.
    """

    def __init__(self, messages: dict[int, bytes], uidvalidity: int = 1001):
        self.messages = messages
        self.uidvalidity = uidvalidity
        self.seen_flags: set[int] = set()
        self.logged_out = False

    def status(self, folder, what):
        return "OK", [f"{folder} (UIDVALIDITY {self.uidvalidity} UIDNEXT {max(self.messages, default=0) + 1})".encode()]

    def select(self, folder, readonly=False):
        return "OK", [b"1"]

    def uid(self, command, *args):
        if command == "search":
            # args = (None, "(UID N:*)")
            criteria = args[-1]
            import re
            match = re.search(r"UID (\d+):\*", criteria)
            start = int(match.group(1)) if match else 1
            matching = sorted(u for u in self.messages if u >= start)
            return "OK", [" ".join(str(u) for u in matching).encode()]
        if command == "fetch":
            uid = int(args[0])
            if uid not in self.messages:
                return "OK", [None]
            return "OK", [(b"1 (RFC822 {n})", self.messages[uid])]
        if command == "store":
            uid = int(args[0])
            self.seen_flags.add(uid)
            return "OK", [b"OK"]
        raise ValueError(f"Unexpected IMAP command: {command}")

    def logout(self):
        self.logged_out = True


def _make_fake_connect(fake_imap: FakeIMAP):
    def _fake_connect(mailbox):
        return fake_imap
    return _fake_connect


def _simple_eml(uid_marker: str, subject: str = "Test", from_addr: str = "someone@example.com") -> bytes:
    return (
        f"From: {from_addr}\r\n"
        f"To: victim@acmecorp.com\r\n"
        f"Subject: {subject}\r\n"
        f"Message-ID: <{uid_marker}@example.com>\r\n"
        f"Content-Type: text/plain\r\n\r\n"
        f"Body content for {uid_marker}.\r\n"
    ).encode()


async def _create_org_admin_and_mailbox(db_session_factory, organization_domain="acmecorp.com"):
    """Helper: creates an org (via register_user-equivalent) + a Mailbox
    row directly against the DB session, bypassing the API layer since
    these are service-level tests.
    """
    pass  # not used -- tests below use the HTTP client + API instead


@pytest.mark.asyncio
async def test_create_and_poll_mailbox_creates_case(client, sample_phish_eml_bytes):
    # Register an org_admin (first registrant of a new org).
    r = await client.post(
        "/api/v1/auth/register",
        json={
            "full_name": "Admin", "email": "admin@acmecorp.com",
            "password": "SuperSecret123!", "organization_name": "Acme Corp",
        },
    )
    token = r.json()["message"].split("verification_token=")[-1]
    await client.post("/api/v1/auth/verify-email", json={"token": token})
    r = await client.post("/api/v1/auth/login", json={"email": "admin@acmecorp.com", "password": "SuperSecret123!"})
    headers = {"Authorization": f"Bearer {r.json()['access_token']}"}

    r = await client.post(
        "/api/v1/mailboxes", headers=headers,
        json={
            "address": "security@acmecorp.com",
            "imap_host": "imap.gmail.com", "imap_port": 993, "imap_use_ssl": True,
            "imap_username": "security@acmecorp.com", "imap_password": "fake-app-password",
        },
    )
    assert r.status_code == 201, r.text
    mailbox_id = r.json()["id"]
    assert r.json()["is_polling_enabled"] is True

    fake_imap = FakeIMAP({1: sample_phish_eml_bytes})
    with patch("app.services.mailbox_polling._connect", _make_fake_connect(fake_imap)):
        r = await client.post(f"/api/v1/mailboxes/{mailbox_id}/poll-now", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["outcomes"]) == 1
    assert body["outcomes"][0]["status"] == "created"
    assert 1 in fake_imap.seen_flags

    case_id = body["outcomes"][0]["case_id"]
    r = await client.get(f"/api/v1/cases/{case_id}/risk-score", headers=headers)
    assert r.status_code == 200
    assert r.json()["classification"] in ("suspicious", "likely_malicious", "malicious")


@pytest.mark.asyncio
async def test_poll_skips_already_seen_uid_on_second_poll(client, sample_benign_eml_bytes):
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
    mailbox_id = r.json()["id"]

    fake_imap = FakeIMAP({1: sample_benign_eml_bytes})
    with patch("app.services.mailbox_polling._connect", _make_fake_connect(fake_imap)):
        r1 = await client.post(f"/api/v1/mailboxes/{mailbox_id}/poll-now", headers=headers)
        assert len(r1.json()["outcomes"]) == 1
        assert r1.json()["outcomes"][0]["status"] == "created"

        # Second poll, same mailbox state (UID 1 already at/below last_seen_uid) -> no new messages.
        r2 = await client.post(f"/api/v1/mailboxes/{mailbox_id}/poll-now", headers=headers)
        assert r2.json()["outcomes"] == []
        assert "no new messages" in r2.json()["message"].lower()


@pytest.mark.asyncio
async def test_forward_as_attachment_extracts_original_message(client):
    """A genuine 'forward as attachment' -- the outer message wraps the
    original as a message/rfc822 part. The ORIGINAL (with its own
    SPF/DKIM-failing headers) must be what gets analyzed, not the
    forwarding envelope.
    """
    original = (
        "From: \"PayPal Security\" <alerts@paypa1-secure.top>\r\n"
        "Reply-To: attacker@totally-different-domain.xyz\r\n"
        "Authentication-Results: mx; spf=fail; dkim=fail; dmarc=fail\r\n"
        "To: victim@acmecorp.com\r\n"
        "Subject: Urgent Action Required\r\n"
        "Message-ID: <original123@paypa1-secure.top>\r\n"
        "Content-Type: text/plain\r\n\r\n"
        "Please verify your account immediately, click http://203.0.113.99/login\r\n"
    ).encode()

    outer = (
        "From: employee@acmecorp.com\r\n"
        "To: security@acmecorp.com\r\n"
        "Subject: Fwd: Urgent Action Required\r\n"
        "Message-ID: <outer456@acmecorp.com>\r\n"
        'Content-Type: multipart/mixed; boundary="BOUNDARY"\r\n\r\n'
        "--BOUNDARY\r\n"
        "Content-Type: text/plain\r\n\r\n"
        "Hi security team, this looks suspicious, please check.\r\n"
        "--BOUNDARY\r\n"
        "Content-Type: message/rfc822\r\n\r\n"
    ).encode() + original + b"\r\n--BOUNDARY--\r\n"

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
        json={"address": "security@acmecorp.com", "imap_host": "imap.gmail.com", "imap_username": "security@acmecorp.com", "imap_password": "x"},
    )
    mailbox_id = r.json()["id"]

    fake_imap = FakeIMAP({1: outer})
    with patch("app.services.mailbox_polling._connect", _make_fake_connect(fake_imap)):
        r = await client.post(f"/api/v1/mailboxes/{mailbox_id}/poll-now", headers=headers)
    case_id = r.json()["outcomes"][0]["case_id"]

    # The case should reflect the ORIGINAL malicious message's risk
    # profile (SPF/DKIM fail, raw IP link), not the benign forwarding note.
    r = await client.get(f"/api/v1/cases/{case_id}/risk-score", headers=headers)
    assert r.json()["classification"] in ("suspicious", "likely_malicious", "malicious")

    r = await client.get(f"/api/v1/cases/{case_id}/findings", headers=headers)
    codes = {f["code"] for f in r.json()}
    assert "SPF_FAIL" in codes


@pytest.mark.asyncio
async def test_mailbox_management_requires_org_admin(client):
    r = await client.post(
        "/api/v1/auth/register",
        json={"full_name": "Admin", "email": "admin@acmecorp.com", "password": "SuperSecret123!", "organization_name": "Acme Corp"},
    )
    admin_token = r.json()["message"].split("verification_token=")[-1]
    await client.post("/api/v1/auth/verify-email", json={"token": admin_token})

    r = await client.post(
        "/api/v1/auth/register",
        json={"full_name": "Bob", "email": "bob@acmecorp.com", "password": "SuperSecret123!", "organization_name": "Acme Corp"},
    )
    bob_token = r.json()["message"].split("verification_token=")[-1]
    await client.post("/api/v1/auth/verify-email", json={"token": bob_token})
    r = await client.post("/api/v1/auth/login", json={"email": "bob@acmecorp.com", "password": "SuperSecret123!"})
    employee_headers = {"Authorization": f"Bearer {r.json()['access_token']}"}

    r = await client.post(
        "/api/v1/mailboxes", headers=employee_headers,
        json={"address": "security@acmecorp.com", "imap_host": "imap.gmail.com", "imap_username": "x", "imap_password": "x"},
    )
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_mailbox_poll_connection_failure_handled_gracefully(client):
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
        json={"address": "security@acmecorp.com", "imap_host": "imap.gmail.com", "imap_username": "x", "imap_password": "wrong"},
    )
    mailbox_id = r.json()["id"]

    def _raise_connect(mailbox):
        raise OSError("Connection refused")

    with patch("app.services.mailbox_polling._connect", _raise_connect):
        r = await client.post(f"/api/v1/mailboxes/{mailbox_id}/poll-now", headers=headers)
    assert r.status_code == 200  # the endpoint itself must not 500
    assert r.json()["outcomes"] == []
    assert "failed" in r.json()["message"].lower()

    r = await client.get("/api/v1/mailboxes", headers=headers)
    assert r.json()[0]["last_poll_status"] == "error"
