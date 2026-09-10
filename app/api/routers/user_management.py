"""Org-scoped user management: listing colleagues and changing their
role. Restricted to org_admin+ and always scoped to the caller's own
organization -- an org_admin can never see or modify a user in a
different tenant, regardless of user ID guessing.
"""
import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.models.rbac import RoleName
from app.models.user import User
from app.schemas.user_management import UpdateUserRoleRequest, UserSummaryOut
from app.security.rbac import require_min_role
from app.services.audit import record_audit_event

router = APIRouter(prefix="/users", tags=["users"])


@router.get("", response_model=list[UserSummaryOut])
async def list_org_users(
    current_user: User = Depends(require_min_role(RoleName.ORG_ADMIN)),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(User).where(User.organization_id == current_user.organization_id).order_by(User.created_at)
    )
    return result.scalars().all()


@router.patch("/{user_id}/role", response_model=UserSummaryOut)
async def update_user_role(
    user_id: uuid.UUID,
    payload: UpdateUserRoleRequest,
    current_user: User = Depends(require_min_role(RoleName.ORG_ADMIN)),
    db: AsyncSession = Depends(get_db),
):
    target = await db.get(User, user_id)
    if target is None or target.organization_id != current_user.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    previous_role = target.role
    target.role = payload.role
    await db.commit()
    await db.refresh(target)

    await record_audit_event(
        db,
        organization_id=current_user.organization_id,
        actor_user_id=current_user.id,
        action="user.role_change",
        resource_type="user",
        resource_id=str(target.id),
        detail={"from_role": previous_role.value, "to_role": target.role.value},
    )
    return target
