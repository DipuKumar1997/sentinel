"""API key management -- creating/listing/revoking keys used for
programmatic email ingestion (see app/services/api_key_service.py and
app/api/routers/ingestion.py). Restricted to org-admin and above: an API
key is a standing credential that can create cases on behalf of the
organization, so issuing one is treated the same as any other
privileged action.
"""
import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.models.alert import ApiKey
from app.models.rbac import RoleName
from app.models.user import User
from app.schemas.api_key import ApiKeyCreatedResponse, ApiKeyOut, CreateApiKeyRequest
from app.security.rbac import require_min_role
from app.services import api_key_service
from app.services.audit import record_audit_event

router = APIRouter(prefix="/api-keys", tags=["api-keys"])


@router.post("", response_model=ApiKeyCreatedResponse, status_code=status.HTTP_201_CREATED)
async def create_api_key(
    payload: CreateApiKeyRequest,
    current_user: User = Depends(require_min_role(RoleName.ORG_ADMIN)),
    db: AsyncSession = Depends(get_db),
):
    api_key, raw_key = await api_key_service.create_api_key(
        db,
        organization_id=current_user.organization_id,
        name=payload.name,
        created_by_user_id=current_user.id,
    )
    await record_audit_event(
        db,
        organization_id=current_user.organization_id,
        actor_user_id=current_user.id,
        action="api_key.create",
        resource_type="api_key",
        resource_id=str(api_key.id),
        detail={"name": api_key.name},
    )
    return ApiKeyCreatedResponse(
        id=api_key.id, name=api_key.name, key_prefix=api_key.key_prefix, raw_key=raw_key
    )


@router.get("", response_model=list[ApiKeyOut])
async def list_api_keys(
    current_user: User = Depends(require_min_role(RoleName.ORG_ADMIN)),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(ApiKey)
        .where(ApiKey.organization_id == current_user.organization_id)
        .order_by(ApiKey.created_at.desc())
    )
    return result.scalars().all()


@router.delete("/{api_key_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_api_key(
    api_key_id: uuid.UUID,
    current_user: User = Depends(require_min_role(RoleName.ORG_ADMIN)),
    db: AsyncSession = Depends(get_db),
):
    try:
        await api_key_service.revoke_api_key(
            db, api_key_id=api_key_id, organization_id=current_user.organization_id
        )
    except api_key_service.ApiKeyError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message) from exc

    await record_audit_event(
        db,
        organization_id=current_user.organization_id,
        actor_user_id=current_user.id,
        action="api_key.revoke",
        resource_type="api_key",
        resource_id=str(api_key_id),
    )
