import enum
import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base_class import Base, TimestampMixin, UUIDPKMixin


class IOCType(str, enum.Enum):
    DOMAIN = "domain"
    IP = "ip"
    URL = "url"
    ATTACHMENT_HASH = "attachment_hash"
    EMAIL_ADDRESS = "email_address"


class Domain(UUIDPKMixin, TimestampMixin, Base):
    __tablename__ = "domains"

    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    registrar: Mapped[str | None] = mapped_column(String(255), nullable=True)
    creation_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    age_days: Mapped[int | None] = mapped_column(Integer, nullable=True)
    is_newly_registered: Mapped[bool] = mapped_column(Boolean, default=False)
    whois_source: Mapped[str | None] = mapped_column(String(64), nullable=True)  # e.g. "whois", "unavailable"
    reputation_score: Mapped[int | None] = mapped_column(Integer, nullable=True)  # 0-100, higher = worse
    last_enriched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class IPAddress(UUIDPKMixin, TimestampMixin, Base):
    __tablename__ = "ips"

    address: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    asn: Mapped[str | None] = mapped_column(String(32), nullable=True)
    asn_org: Mapped[str | None] = mapped_column(String(255), nullable=True)
    country: Mapped[str | None] = mapped_column(String(8), nullable=True)
    # Coarse, provider-reported geolocation ONLY. This is infrastructure
    # geolocation (hosting/ASN), never a claim about a physical attacker.
    approx_city: Mapped[str | None] = mapped_column(String(128), nullable=True)
    approx_lat: Mapped[float | None] = mapped_column(nullable=True)
    approx_lon: Mapped[float | None] = mapped_column(nullable=True)
    geolocation_confidence: Mapped[str] = mapped_column(String(16), default="low")
    geolocation_source: Mapped[str | None] = mapped_column(String(64), nullable=True)  # e.g. "ipinfo", "unavailable"
    reputation_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    is_known_malicious: Mapped[bool] = mapped_column(Boolean, default=False)

    # Reverse DNS / hosting classification -- see app/services/dns_forensics.py
    # and app/services/ip_intelligence.py. All nullable and left unset
    # ("unavailable") rather than guessed when the underlying lookup fails
    # or no data source is configured.
    ptr_hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    hosting_classification: Mapped[str | None] = mapped_column(String(32), nullable=True)  # hosting_datacenter|residential|unknown
    hosting_classification_source: Mapped[str | None] = mapped_column(String(64), nullable=True)
    is_vpn_or_proxy_suspected: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    is_tor_exit_node_suspected: Mapped[bool | None] = mapped_column(Boolean, nullable=True)

    last_enriched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class URLRecord(UUIDPKMixin, TimestampMixin, Base):
    __tablename__ = "urls"

    full_url: Mapped[str] = mapped_column(Text, nullable=False)
    normalized_url: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    domain_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("domains.id"), nullable=True)
    is_shortened: Mapped[bool] = mapped_column(Boolean, default=False)
    redirect_chain: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON-encoded
    reputation_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    scanned_safely: Mapped[bool] = mapped_column(Boolean, default=False)


class Attachment(UUIDPKMixin, TimestampMixin, Base):
    __tablename__ = "attachments"

    email_message_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("email_messages.id", ondelete="CASCADE"), nullable=False, index=True
    )
    evidence_object_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("evidence_objects.id"), nullable=False
    )
    filename: Mapped[str | None] = mapped_column(String(512), nullable=True)
    declared_mime_type: Mapped[str | None] = mapped_column(String(128), nullable=True)
    detected_mime_type: Mapped[str | None] = mapped_column(String(128), nullable=True)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    is_archive: Mapped[bool] = mapped_column(Boolean, default=False)
    is_macro_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    mime_type_mismatch: Mapped[bool] = mapped_column(Boolean, default=False)
    reputation_score: Mapped[int | None] = mapped_column(Integer, nullable=True)


class IOCRecord(UUIDPKMixin, TimestampMixin, Base):
    """Unified indicator-of-compromise record linking a case to a concrete
    entity (domain/ip/url/attachment/email address) for fast lookup and
    cross-case correlation.
    """

    __tablename__ = "ioc_records"

    case_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True
    )
    ioc_type: Mapped[IOCType] = mapped_column(Enum(IOCType, name="ioc_type"), nullable=False)
    value: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    domain_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("domains.id"), nullable=True)
    ip_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("ips.id"), nullable=True)
    url_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("urls.id"), nullable=True)
    attachment_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("attachments.id"), nullable=True
    )
    first_seen_in_case: Mapped[bool] = mapped_column(Boolean, default=True)


class ThreatIntelligenceObservation(UUIDPKMixin, TimestampMixin, Base):
    """A single observation returned by an external/internal threat intel
    source about an IOC. Kept append-only for auditability.
    """

    __tablename__ = "threat_intelligence_observations"

    ioc_record_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("ioc_records.id", ondelete="CASCADE"), nullable=False, index=True
    )
    provider: Mapped[str] = mapped_column(String(64), nullable=False)  # e.g. virustotal, abuseipdb, internal_demo
    verdict: Mapped[str] = mapped_column(String(32), nullable=False)  # malicious|suspicious|clean|unknown
    raw_response: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON-encoded
    is_synthetic_demo_data: Mapped[bool] = mapped_column(Boolean, default=False)


class DNSObservation(UUIDPKMixin, TimestampMixin, Base):
    """A single passive DNS query result, recorded append-only for
    auditability -- never fabricated. If a lookup fails, `success=False`
    and `error_detail` records why, rather than silently omitting the row.
    """

    __tablename__ = "dns_observations"

    case_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True
    )
    query_type: Mapped[str] = mapped_column(String(16), nullable=False)  # A|AAAA|MX|NS|TXT|CNAME|PTR
    query_name: Mapped[str] = mapped_column(String(255), nullable=False)
    result: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON-encoded list of answers
    success: Mapped[bool] = mapped_column(Boolean, nullable=False)
    source: Mapped[str] = mapped_column(String(64), default="dnspython")
    ttl: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error_detail: Mapped[str | None] = mapped_column(Text, nullable=True)


class BlockchainAnchor(Base):
    """Append-only hash-chain evidence-integrity ledger.

    This is explicitly a per-organization HASH CHAIN (each entry commits
    to the previous entry's hash, exactly like a blockchain's core
    linking mechanism), not a distributed/consensus blockchain network --
    see docs and the "blockchain" section of README for why that
    distinction matters and why it's the honest description of what
    this actually is. No email content, bodies, or attachments are ever
    anchored -- only SHA-256 hashes already computed elsewhere.
    """

    __tablename__ = "blockchain_anchors"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    case_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("cases.id"), nullable=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)  # case_created|report_generated
    evidence_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    report_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    previous_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    computed_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    # Exact Unix-epoch float used as the hash input, stored separately
    # from `created_at` (a DateTime) because DateTime values can lose
    # timezone-offset precision on round-trip through some database
    # backends (observed with SQLite dropping the UTC offset on
    # read-back), which would make hash recomputation non-reproducible
    # and cause false "tampering detected" results. A plain float has
    # no such ambiguity.
    hash_timestamp: Mapped[float] = mapped_column(nullable=False)
