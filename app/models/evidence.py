import enum
import uuid

from sqlalchemy import Enum, ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base_class import Base, TimestampMixin, UUIDPKMixin


class EvidenceKind(str, enum.Enum):
    RAW_EMAIL = "raw_email"
    ATTACHMENT = "attachment"
    RENDERED_HTML = "rendered_html"
    SCREENSHOT = "screenshot"
    REPORT_EXPORT = "report_export"


class EvidenceObject(UUIDPKMixin, TimestampMixin, Base):
    """A preserved, immutable evidence artifact.

    The original bytes are never mutated in place. Any normalization
    (e.g. parsed headers) is stored as *derived* data referencing this
    object, never overwriting it. `storage_uri` points at the local
    filesystem in development or an S3-compatible bucket in production.
    """

    __tablename__ = "evidence_objects"

    case_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True
    )
    kind: Mapped[EvidenceKind] = mapped_column(Enum(EvidenceKind, name="evidence_kind"), nullable=False)
    original_filename: Mapped[str | None] = mapped_column(String(512), nullable=True)
    content_type: Mapped[str | None] = mapped_column(String(128), nullable=True)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    storage_uri: Mapped[str] = mapped_column(String(1024), nullable=False)

    # Chain-of-custody: who/what ingested it.
    ingested_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=True
    )
    ingest_method: Mapped[str] = mapped_column(String(32), default="upload")  # upload|forward|api

    hashes: Mapped[list["EvidenceHash"]] = relationship(back_populates="evidence_object")


class EvidenceHash(UUIDPKMixin, TimestampMixin, Base):
    """Cryptographic hashes recorded at ingest time for integrity verification."""

    __tablename__ = "evidence_hashes"

    evidence_object_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("evidence_objects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    algorithm: Mapped[str] = mapped_column(String(16), default="sha256")
    hex_digest: Mapped[str] = mapped_column(String(128), nullable=False, index=True)

    evidence_object: Mapped["EvidenceObject"] = relationship(back_populates="hashes")


class RetentionPolicy(UUIDPKMixin, TimestampMixin, Base):
    __tablename__ = "retention_policies"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    retain_days: Mapped[int] = mapped_column(Integer, nullable=False, default=365)
    applies_to: Mapped[str] = mapped_column(String(64), default="evidence_objects")
