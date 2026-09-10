import enum
import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base_class import Base, TimestampMixin, UUIDPKMixin


class EmailMessage(UUIDPKMixin, TimestampMixin, Base):
    """Normalized representation of the parsed suspicious email.

    Always linked back to its raw EvidenceObject so nothing here is ever
    treated as ground truth without the ability to re-derive it from the
    original bytes.
    """

    __tablename__ = "email_messages"

    case_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True
    )
    raw_evidence_object_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("evidence_objects.id"), nullable=False
    )

    message_id: Mapped[str | None] = mapped_column(String(998), nullable=True, index=True)
    subject: Mapped[str | None] = mapped_column(Text, nullable=True)
    date_header: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    from_display_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    from_address: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    reply_to_address: Mapped[str | None] = mapped_column(String(255), nullable=True)
    return_path: Mapped[str | None] = mapped_column(String(255), nullable=True)

    to_addresses: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON-encoded list
    cc_addresses: Mapped[str | None] = mapped_column(Text, nullable=True)

    body_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    body_html: Mapped[str | None] = mapped_column(Text, nullable=True)

    has_attachments: Mapped[bool] = mapped_column(Boolean, default=False)
    attachment_count: Mapped[int] = mapped_column(Integer, default=0)


class EmailHeader(UUIDPKMixin, TimestampMixin, Base):
    """Every raw header, preserved verbatim and in original order."""

    __tablename__ = "email_headers"

    email_message_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("email_messages.id", ondelete="CASCADE"), nullable=False, index=True
    )
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    value: Mapped[str] = mapped_column(Text, nullable=False)


class ReceivedHop(UUIDPKMixin, TimestampMixin, Base):
    """One parsed hop from the reconstructed Received: header chain."""

    __tablename__ = "received_hops"

    email_message_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("email_messages.id", ondelete="CASCADE"), nullable=False, index=True
    )
    hop_index: Mapped[int] = mapped_column(Integer, nullable=False)  # 0 = closest to recipient
    raw_value: Mapped[str] = mapped_column(Text, nullable=False)

    from_host: Mapped[str | None] = mapped_column(String(255), nullable=True)
    from_ip: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    by_host: Mapped[str | None] = mapped_column(String(255), nullable=True)
    with_protocol: Mapped[str | None] = mapped_column(String(64), nullable=True)
    timestamp: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    is_internal_relay: Mapped[bool] = mapped_column(Boolean, default=False)
    parse_confidence: Mapped[str] = mapped_column(String(16), default="high")  # high|medium|low


class SenderIdentity(UUIDPKMixin, TimestampMixin, Base):
    """Untrusted identity signals extracted from the suspicious email itself.

    This is deliberately separate from `User` -- it is *never* an
    authenticated account, only a set of claims (From/Reply-To/display
    name/etc.) worth correlating against history and threat intel.
    """

    __tablename__ = "sender_identities"

    email_message_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("email_messages.id", ondelete="CASCADE"), nullable=False, index=True
    )
    claimed_display_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    claimed_address: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    claimed_organization_lookalike: Mapped[bool] = mapped_column(Boolean, default=False)
    display_name_address_mismatch: Mapped[bool] = mapped_column(Boolean, default=False)


class AuthenticationResult(UUIDPKMixin, TimestampMixin, Base):
    """SPF/DKIM/DMARC evaluation outcomes for a message."""

    __tablename__ = "authentication_results"

    email_message_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("email_messages.id", ondelete="CASCADE"), nullable=False, index=True
    )
    mechanism: Mapped[str] = mapped_column(String(16), nullable=False)  # spf|dkim|dmarc
    result: Mapped[str] = mapped_column(String(32), nullable=False)  # pass|fail|softfail|neutral|none|temperror|permerror|unavailable
    domain: Mapped[str | None] = mapped_column(String(255), nullable=True)
    raw_detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    source: Mapped[str] = mapped_column(String(32), default="header")  # header|live_check
