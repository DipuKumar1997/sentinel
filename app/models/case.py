import enum
import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base_class import Base, TimestampMixin, UUIDPKMixin


class CaseStatus(str, enum.Enum):
    NEW = "new"
    TRIAGE = "triage"
    ANALYZING = "analyzing"
    UNDER_INVESTIGATION = "under_investigation"
    ESCALATED = "escalated"
    RESOLVED_MALICIOUS = "resolved_malicious"
    RESOLVED_BENIGN = "resolved_benign"
    CLOSED = "closed"


class Mailbox(UUIDPKMixin, TimestampMixin, Base):
    """A dedicated security mailbox an organization forwards suspicious
    mail to, which this platform polls over IMAP and turns into cases.

    Credentials are never stored in plaintext -- `encrypted_password` is
    a Fernet-encrypted blob (see app/security/secret_encryption.py),
    keyed off the application's own SECRET_KEY. Polling state
    (`last_seen_uid`/`uid_validity`) follows the IMAP UID model so
    restarts/re-polls never reprocess or skip messages.
    """

    __tablename__ = "mailboxes"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    address: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(String(255), nullable=True)
    is_active: Mapped[bool] = mapped_column(default=True)

    # IMAP connection details.
    imap_host: Mapped[str | None] = mapped_column(String(255), nullable=True)
    imap_port: Mapped[int] = mapped_column(Integer, default=993)
    imap_use_ssl: Mapped[bool] = mapped_column(Boolean, default=True)
    imap_username: Mapped[str | None] = mapped_column(String(255), nullable=True)
    encrypted_password: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    imap_folder: Mapped[str] = mapped_column(String(255), default="INBOX")

    # Polling state.
    is_polling_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    poll_interval_seconds: Mapped[int] = mapped_column(Integer, default=120)
    last_polled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_poll_status: Mapped[str | None] = mapped_column(String(32), nullable=True)  # ok|error
    last_poll_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    uid_validity: Mapped[int | None] = mapped_column(Integer, nullable=True)
    last_seen_uid: Mapped[int] = mapped_column(Integer, default=0)

    # Cases created from this mailbox are attributed to a dedicated,
    # non-loginable service-account user (same pattern as ApiKey), so
    # "who reported this" is never confused with "who the email claims
    # to be from" -- see docs/architecture.md section 3.
    service_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=True
    )


class MailboxProcessedMessage(UUIDPKMixin, TimestampMixin, Base):
    """Append-only de-duplication record: one row per IMAP message this
    platform has already turned into a case (or deliberately skipped).
    Primary de-dup key is (mailbox_id, imap_uid) since IMAP UIDs are
    stable and unique within one UIDVALIDITY epoch; Message-ID and
    evidence hash are recorded too as secondary, human-inspectable
    corroboration.
    """

    __tablename__ = "mailbox_processed_messages"

    mailbox_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("mailboxes.id", ondelete="CASCADE"), nullable=False, index=True
    )
    imap_uid: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    message_id_header: Mapped[str | None] = mapped_column(String(998), nullable=True)
    evidence_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    case_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("cases.id"), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="created")  # created|skipped_duplicate|error
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)


class Case(UUIDPKMixin, TimestampMixin, Base):
    """An investigation case, created when a registered reporter submits a
    suspicious email. One case wraps exactly one submitted email plus all
    derived evidence/analysis/findings.
    """

    __tablename__ = "cases"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    case_number: Mapped[str] = mapped_column(String(32), unique=True, nullable=False, index=True)

    # REPORTER: the authenticated platform user who submitted this case.
    # This is verified via login/session -- NEVER derived from the email's
    # own From header.
    reporter_user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=False, index=True
    )

    assigned_analyst_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=True
    )

    status: Mapped[CaseStatus] = mapped_column(
        Enum(CaseStatus, name="case_status"), default=CaseStatus.NEW, nullable=False, index=True
    )
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    priority: Mapped[str] = mapped_column(String(16), default="medium")

    reporter: Mapped["User"] = relationship(foreign_keys=[reporter_user_id])
    assigned_analyst: Mapped["User | None"] = relationship(foreign_keys=[assigned_analyst_id])


class CaseStatusHistory(UUIDPKMixin, TimestampMixin, Base):
    __tablename__ = "case_status_history"

    case_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True
    )
    from_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    to_status: Mapped[str] = mapped_column(String(32), nullable=False)
    changed_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=True
    )
    note: Mapped[str | None] = mapped_column(Text, nullable=True)


class Note(UUIDPKMixin, TimestampMixin, Base):
    __tablename__ = "notes"

    case_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True
    )
    author_user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)


class Tag(UUIDPKMixin, TimestampMixin, Base):
    __tablename__ = "tags"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(64), nullable=False)


class CaseTag(Base):
    __tablename__ = "case_tags"

    case_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("cases.id", ondelete="CASCADE"), primary_key=True
    )
    tag_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tags.id", ondelete="CASCADE"), primary_key=True
    )
