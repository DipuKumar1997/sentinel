import uuid
from dataclasses import dataclass

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import APIKeyHeader, OAuth2PasswordBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.models.user import AccountStatus, User
from app.security.tokens import TokenError, decode_access_token

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login", auto_error=False)
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def get_current_user(
    token: str = Depends(oauth2_scheme), db: AsyncSession = Depends(get_db)
) -> User:
    credentials_error = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if not token:
        raise credentials_error
    try:
        payload = decode_access_token(token)
    except TokenError as exc:
        raise credentials_error from exc

    user_id = payload.get("sub")
    if not user_id:
        raise credentials_error

    result = await db.execute(select(User).where(User.id == uuid.UUID(user_id)))
    user = result.scalar_one_or_none()
    if user is None:
        raise credentials_error
    if user.status != AccountStatus.ACTIVE:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Account is {user.status.value}, not active.",
        )
    return user


@dataclass
class ActorContext:
    """Whoever/whatever is making an ingestion request -- either an
    authenticated human (JWT) or a programmatic integration (API key).
    Both resolve to a real organization_id + reporter_user_id so the
    rest of the pipeline (Case, audit log, tenant isolation) never has
    to special-case which kind of caller it was.
    """
    organization_id: uuid.UUID
    reporter_user_id: uuid.UUID
    is_api_key: bool
    api_key_name: str | None = None


async def get_current_actor(
    bearer_token: str | None = Depends(oauth2_scheme),
    api_key: str | None = Security(api_key_header),
    db: AsyncSession = Depends(get_db),
) -> ActorContext:
    """Accepts EITHER a Bearer JWT OR an `X-API-Key` header. Exactly one
    must be valid; if both are absent, this fails the same way
    `get_current_user` does (401), so ingestion endpoints using this
    dependency have identical "must be authenticated somehow" semantics
    to every other protected endpoint -- just with a second valid form
    of credential.
    """
    if api_key:
        from app.services.api_key_service import ApiKeyError, resolve_api_key

        try:
            resolved = await resolve_api_key(db, raw_key=api_key)
        except ApiKeyError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.message) from exc
        return ActorContext(
            organization_id=resolved.organization_id,
            reporter_user_id=resolved.service_user_id,
            is_api_key=True,
            api_key_name=resolved.name,
        )

    user = await get_current_user(token=bearer_token, db=db)
    return ActorContext(
        organization_id=user.organization_id,
        reporter_user_id=user.id,
        is_api_key=False,
    )
