"""Append-only audit log writer used across services/routers."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.alert import AuditLog


async def record_audit_event(
    db: AsyncSession,
    *,
    action: str,
    resource_type: str,
    resource_id: str | None = None,
    organization_id: uuid.UUID | None = None,
    actor_user_id: uuid.UUID | None = None,
    ip_address: str | None = None,
    detail: dict | None = None,
    correlation_id: str | None = None,
) -> None:
    entry = AuditLog(
        id=uuid.uuid4(),
        created_at=datetime.now(timezone.utc),
        organization_id=organization_id,
        actor_user_id=actor_user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        ip_address=ip_address,
        detail=json.dumps(detail) if detail is not None else None,
        correlation_id=correlation_id,
    )
    db.add(entry)
    await db.commit()
