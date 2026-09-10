import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.models.campaign import Campaign, CampaignMembership
from app.models.user import User
from app.security.deps import get_current_user

router = APIRouter(prefix="/campaigns", tags=["campaigns"])


@router.get("")
async def list_campaigns(
    current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)
):
    result = await db.execute(
        select(Campaign)
        .where(Campaign.organization_id == current_user.organization_id)
        .order_by(Campaign.last_seen_at.desc())
    )
    campaigns = result.scalars().all()
    return [
        {
            "id": str(c.id),
            "name": c.name,
            "description": c.description,
            "detection_method": c.detection_method,
            "confidence": c.confidence,
            "is_active": c.is_active,
            "first_seen_at": c.first_seen_at,
            "last_seen_at": c.last_seen_at,
        }
        for c in campaigns
    ]


@router.get("/{campaign_id}/cases")
async def get_campaign_cases(
    campaign_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    campaign = await db.get(Campaign, campaign_id)
    if campaign is None or campaign.organization_id != current_user.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Campaign not found.")

    memberships = (
        await db.execute(select(CampaignMembership).where(CampaignMembership.campaign_id == campaign_id))
    ).scalars().all()

    return [
        {
            "case_id": str(m.case_id),
            "similarity_score": m.similarity_score,
            "match_reason": m.match_reason,
        }
        for m in memberships
    ]
