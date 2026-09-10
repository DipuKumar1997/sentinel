import enum
import uuid
from datetime import datetime

from sqlalchemy import DateTime, Enum, Float, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base_class import Base, TimestampMixin, UUIDPKMixin


class Campaign(UUIDPKMixin, TimestampMixin, Base):
    """A cluster of cases believed to share a common origin/infrastructure
    or tactic, detected via shared IOCs, sender patterns, or content
    similarity -- never asserted as a single confirmed attacker identity.
    """

    __tablename__ = "campaigns"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    detection_method: Mapped[str] = mapped_column(String(64), nullable=False)  # shared_ioc|content_similarity|sender_pattern
    first_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    is_active: Mapped[bool] = mapped_column(default=True)


class CampaignMembership(UUIDPKMixin, TimestampMixin, Base):
    __tablename__ = "campaign_memberships"

    campaign_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("campaigns.id", ondelete="CASCADE"), nullable=False, index=True
    )
    case_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True
    )
    similarity_score: Mapped[float] = mapped_column(Float, default=0.0)
    match_reason: Mapped[str | None] = mapped_column(Text, nullable=True)


class GraphEntity(UUIDPKMixin, TimestampMixin, Base):
    """A node in the evidence correlation graph.

    entity_type examples: case, sender_identity, domain, ip, url,
    attachment_hash, campaign.
    """

    __tablename__ = "graph_entities"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    entity_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    entity_ref_id: Mapped[str] = mapped_column(String(64), nullable=False)  # PK of referenced row, as text
    label: Mapped[str] = mapped_column(String(255), nullable=False)


class GraphRelationship(UUIDPKMixin, TimestampMixin, Base):
    """An edge in the evidence correlation graph."""

    __tablename__ = "graph_relationships"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    source_entity_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("graph_entities.id", ondelete="CASCADE"), nullable=False, index=True
    )
    target_entity_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("graph_entities.id", ondelete="CASCADE"), nullable=False, index=True
    )
    relationship_type: Mapped[str] = mapped_column(String(64), nullable=False)  # e.g. sent_from, resolves_to, shares_hash
    weight: Mapped[float] = mapped_column(Float, default=1.0)
