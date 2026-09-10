"""Unit tests for app.services.msg_parser.

Constructing a real Outlook .msg (OLE compound binary) file from scratch
is impractical for a unit test, so we mock `extract_msg.Message` itself
and verify the field-mapping/transformation logic that turns its output
into our shared `ParsedEmail` shape -- that mapping is the actual code
this module is responsible for; `extract_msg`'s own binary parsing is
already covered by its own upstream test suite.
"""
from unittest.mock import MagicMock, patch

from app.services import msg_parser


def _fake_msg(**overrides):
    defaults = dict(
        header=(
            "From: \"PayPal Security\" <alerts@paypa1-secure.top>\r\n"
            "Reply-To: attacker@totally-different-domain.xyz\r\n"
            "Return-Path: <bounce@paypa1-secure.top>\r\n"
            "Message-ID: <abc123@paypa1-secure.top>\r\n"
            "Received: from mail.suspicious-host.ru (mail.suspicious-host.ru [203.0.113.55]) "
            "by mx.acmecorp.com; Mon, 01 Sep 2025 10:15:00 +0000\r\n"
        ),
        sender_email="alerts@paypa1-secure.top",
        sender_name="PayPal Security",
        sender="\"PayPal Security\" <alerts@paypa1-secure.top>",
        to="victim@acmecorp.com",
        cc="",
        date="Mon, 01 Sep 2025 10:14:55 +0000",
        subject="Urgent Action Required",
        body="Please verify your account immediately by clicking here.",
        htmlBody=b"<p>Please verify your account immediately.</p>",
        attachments=[],
    )
    defaults.update(overrides)
    m = MagicMock()
    for key, value in defaults.items():
        setattr(m, key, value)
    m.close = MagicMock()
    return m


def test_parse_msg_bytes_maps_core_fields():
    fake = _fake_msg()
    with patch("app.services.msg_parser.extract_msg.Message", return_value=fake):
        parsed = msg_parser.parse_msg_bytes(b"fake msg bytes")

    assert parsed.from_address == "alerts@paypa1-secure.top"
    assert parsed.from_display_name == "PayPal Security"
    assert parsed.reply_to_address == "attacker@totally-different-domain.xyz"
    assert parsed.return_path == "bounce@paypa1-secure.top"
    assert parsed.message_id == "<abc123@paypa1-secure.top>"
    assert parsed.subject == "Urgent Action Required"
    assert parsed.to_addresses == ["victim@acmecorp.com"]
    assert len(parsed.received_hops) == 1
    assert parsed.received_hops[0].from_ip == "203.0.113.55"
    fake.close.assert_called_once()


def test_parse_msg_bytes_handles_attachments():
    fake_attachment = MagicMock()
    fake_attachment.longFilename = "invoice.zip"
    fake_attachment.shortFilename = "invoice.zip"
    fake_attachment.data = b"PK\x03\x04fakezipcontent"

    fake = _fake_msg(attachments=[fake_attachment])
    with patch("app.services.msg_parser.extract_msg.Message", return_value=fake):
        parsed = msg_parser.parse_msg_bytes(b"fake msg bytes")

    assert len(parsed.attachments) == 1
    assert parsed.attachments[0].filename == "invoice.zip"
    assert parsed.attachments[0].is_archive is True
    assert parsed.attachments[0].payload == b"PK\x03\x04fakezipcontent"


def test_parse_msg_bytes_skips_malformed_attachment_without_failing():
    bad_attachment = MagicMock()
    bad_attachment.longFilename = "broken.bin"
    bad_attachment.shortFilename = "broken.bin"
    type(bad_attachment).data = property(lambda self: (_ for _ in ()).throw(RuntimeError("corrupt")))

    fake = _fake_msg(attachments=[bad_attachment])
    with patch("app.services.msg_parser.extract_msg.Message", return_value=fake):
        parsed = msg_parser.parse_msg_bytes(b"fake msg bytes")

    assert parsed.attachments == []
