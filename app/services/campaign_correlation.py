"""Cross-case correlation: groups cases that share concrete IOCs into a
Campaign, and materializes the evidence-correlation graph (GraphEntity /
GraphRelationship) so future graph queries ("what else touched this
domain?") don't need ad-hoc joins across five tables.

Runs synchronously right after a case's IOCs are persisted, scoped to
one organization at a time (no cross-tenant correlation) -- see
docs/architecture.md section 3 for why tenant isolation is a hard rule
everywhere in this codebase, including here.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.campaign import Campaign, CampaignMembership, GraphEntity, GraphRelationship
from app.models.ioc import IOCRecord

_LOOKBACK_DAYS = 30
_MIN_SHARED_IOCS_FOR_CAMPAIGN = 1


async def _get_or_create_graph_entity(
    db: AsyncSession, organization_id: uuid.UUID, entity_type: str, entity_ref_id: str, label: str
) -> GraphEntity:
    entity = await db.scalar(
        select(GraphEntity).where(
            GraphEntity.organization_id == organization_id,
            GraphEntity.entity_type == entity_type,
            GraphEntity.entity_ref_id == entity_ref_id,
        )
    )
    if entity is None:
        entity = GraphEntity(
            organization_id=organization_id, entity_type=entity_type, entity_ref_id=entity_ref_id, label=label
        )
        db.add(entity)
        await db.flush()
    return entity


async def _get_or_create_relationship(
    db: AsyncSession,
    organization_id: uuid.UUID,
    source_id: uuid.UUID,
    target_id: uuid.UUID,
    relationship_type: str,
) -> None:
    existing = await db.scalar(
        select(GraphRelationship).where(
            GraphRelationship.organization_id == organization_id,
            GraphRelationship.source_entity_id == source_id,
            GraphRelationship.target_entity_id == target_id,
            GraphRelationship.relationship_type == relationship_type,
        )
    )
    if existing is None:
        db.add(
            GraphRelationship(
                organization_id=organization_id,
                source_entity_id=source_id,
                target_entity_id=target_id,
                relationship_type=relationship_type,
                weight=1.0,
            )
        )
    else:
        existing.weight += 1.0


async def build_graph_for_case(
    db: AsyncSession, *, organization_id: uuid.UUID, case_id: uuid.UUID, ioc_records: list[IOCRecord]
) -> None:
    """Adds this case and each of its IOCs as graph nodes, with an edge
    from the case to each IOC. Kept deliberately simple (case -> IOC
    edges only, no IOC -> IOC edges) for this checkpoint -- see
    NEXT_STEPS.md for richer relationship types (e.g. domain resolves_to
    ip) once DNS resolution data is available.
    """
    case_entity = await _get_or_create_graph_entity(
        db, organization_id, "case", str(case_id), f"Case {case_id}"
    )

    for record in ioc_records:
        ioc_entity = await _get_or_create_graph_entity(
            db, organization_id, record.ioc_type.value, str(record.id), record.value
        )
        await _get_or_create_relationship(
            db, organization_id, case_entity.id, ioc_entity.id, "case_has_ioc"
        )


async def correlate_case_into_campaigns(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    case_id: uuid.UUID,
    ioc_records: list[IOCRecord],
) -> Campaign | None:
    """Finds other recent cases in the same organization sharing at least
    one IOC value with this case, and groups them into a Campaign.

    Uses exact IOC value matches only (domain/ip/url/attachment-hash
    equality) -- similarity scoring beyond exact match (e.g. fuzzy
    content similarity) is deferred; see NEXT_STEPS.md.
    """
    if not ioc_records:
        return None

    ioc_values = [r.value for r in ioc_records]
    cutoff = datetime.now(timezone.utc) - timedelta(days=_LOOKBACK_DAYS)

    matching_records = (
        await db.execute(
            select(IOCRecord).where(
                IOCRecord.value.in_(ioc_values),
                IOCRecord.case_id != case_id,
                IOCRecord.created_at >= cutoff,
            )
        )
    ).scalars().all()

    related_case_ids = {r.case_id for r in matching_records}
    if len(related_case_ids) < _MIN_SHARED_IOCS_FOR_CAMPAIGN:
        return None

    shared_value_counts: dict[uuid.UUID, int] = {}
    for r in matching_records:
        shared_value_counts[r.case_id] = shared_value_counts.get(r.case_id, 0) + 1

    existing_membership = (
        await db.execute(
            select(CampaignMembership).where(CampaignMembership.case_id.in_(related_case_ids))
        )
    ).scalars().all()

    campaign: Campaign | None = None
    if existing_membership:
        campaign = await db.get(Campaign, existing_membership[0].campaign_id)

    if campaign is None:
        campaign = Campaign(
            organization_id=organization_id,
            name=f"Campaign detected {datetime.now(timezone.utc).strftime('%Y-%m-%d')} (shared IOCs)",
            description=(
                f"Auto-detected cluster: {len(related_case_ids) + 1} cases share at least one "
                "indicator of compromise (domain/IP/URL/attachment hash)."
            ),
            detection_method="shared_ioc",
            first_seen_at=datetime.now(timezone.utc),
            last_seen_at=datetime.now(timezone.utc),
            confidence=min(0.9, 0.4 + 0.1 * len(related_case_ids)),
            is_active=True,
        )
        db.add(campaign)
        await db.flush()

        for related_case_id, shared_count in shared_value_counts.items():
            db.add(
                CampaignMembership(
                    campaign_id=campaign.id,
                    case_id=related_case_id,
                    similarity_score=min(1.0, shared_count / max(len(ioc_values), 1)),
                    match_reason=f"{shared_count} shared IOC value(s)",
                )
            )
    else:
        campaign.last_seen_at = datetime.now(timezone.utc)

    total_shared = sum(shared_value_counts.values())
    db.add(
        CampaignMembership(
            campaign_id=campaign.id,
            case_id=case_id,
            similarity_score=min(1.0, total_shared / max(len(ioc_values), 1)),
            match_reason=f"{total_shared} shared IOC value(s) across {len(related_case_ids)} case(s)",
        )
    )

    return campaign
