"""API-key issuance and verification for programmatic (non-interactive)
email ingestion -- the third of the three intake modes: (1) authenticated
human upload via the dashboard/API, (2) [not yet implemented -- see
NEXT_STEPS.md] forward-to-mailbox, (3) this one: a security tool or mail
gateway posting `.eml`/`.msg` bytes directly with an API key, no human
login involved.

Every API key is tied to a dedicated, non-loginable "service account"
User row (see ApiKey.service_user_id) so cases created through it are
still attributed to a real `reporter_user_id` for audit/history
purposes -- never anonymous, never re-using a real human's identity.
"""
from __future__ import annotations

import hashlib
import secrets
import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.alert import ApiKey
from app.models.rbac import RoleName
from app.models.user import AccountStatus, User
from app.security.passwords import hash_password

_KEY_PREFIX = "sm_live_"


class ApiKeyError(Exception):
    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


def _hash_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode()).hexdigest()


async def create_api_key(
    db: AsyncSession, *, organization_id: uuid.UUID, name: str, created_by_user_id: uuid.UUID
) -> tuple[ApiKey, str]:
    """Creates a new API key plus its backing service-account user.

    The service account has an unusable password (a random value never
    given to anyone) so it can never be used to log in directly via
    /auth/login -- its only purpose is to exist as a valid FK target for
    Case.reporter_user_id.
    """
    raw_key = _KEY_PREFIX + secrets.token_urlsafe(32)
    hashed = _hash_key(raw_key)
    prefix_display = raw_key[: len(_KEY_PREFIX) + 6]

    service_user = User(
        organization_id=organization_id,
        email=f"api-key-{uuid.uuid4().hex[:12]}@service.internal",
        full_name=f"API integration: {name}",
        hashed_password=hash_password(secrets.token_urlsafe(32)),  # unusable, never shared
        role=RoleName.EMPLOYEE,
        status=AccountStatus.ACTIVE,
        is_email_verified=True,
    )
    db.add(service_user)
    await db.flush()

    api_key = ApiKey(
        organization_id=organization_id,
        name=name,
        key_prefix=prefix_display,
        hashed_key=hashed,
        scopes="ingest:email",
        is_active=True,
        service_user_id=service_user.id,
        created_by_user_id=created_by_user_id,
    )
    db.add(api_key)
    await db.commit()
    await db.refresh(api_key)

    return api_key, raw_key


async def resolve_api_key(db: AsyncSession, *, raw_key: str) -> ApiKey:
    """Looks up and validates an API key, returning the ApiKey row (with
    `.service_user_id` populated) if it's active. Raises ApiKeyError
    (never returns a partially-valid state) otherwise.
    """
    if not raw_key.startswith(_KEY_PREFIX):
        raise ApiKeyError("Invalid API key format.", 401)

    hashed = _hash_key(raw_key)
    api_key = await db.scalar(select(ApiKey).where(ApiKey.hashed_key == hashed))
    if api_key is None or not api_key.is_active:
        raise ApiKeyError("Invalid or revoked API key.", 401)

    from datetime import datetime, timezone

    api_key.last_used_at = datetime.now(timezone.utc)
    await db.commit()

    return api_key


async def revoke_api_key(db: AsyncSession, *, api_key_id: uuid.UUID, organization_id: uuid.UUID) -> None:
    api_key = await db.get(ApiKey, api_key_id)
    if api_key is None or api_key.organization_id != organization_id:
        raise ApiKeyError("API key not found.", 404)
    api_key.is_active = False
    await db.commit()
