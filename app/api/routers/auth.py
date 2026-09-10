"""Registration, email verification, login, and token refresh endpoints."""
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.limiter import limiter
from app.db.session import get_db
from app.schemas.auth import (
    LoginRequest,
    RefreshRequest,
    RegisterRequest,
    RegisterResponse,
    TokenResponse,
    UserOut,
    VerifyEmailRequest,
)
from app.security.deps import get_current_user
from app.services import auth_service
from app.services.audit import record_audit_event

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", response_model=RegisterResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit("10/minute")
async def register(request: Request, payload: RegisterRequest, db: AsyncSession = Depends(get_db)):
    try:
        user, raw_verification_token = await auth_service.register_user(
            db,
            full_name=payload.full_name,
            email=payload.email,
            password=payload.password,
            organization_name=payload.organization_name,
        )
    except auth_service.AuthError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message) from exc

    await record_audit_event(
        db, organization_id=user.organization_id, actor_user_id=user.id,
        action="user.register", resource_type="user", resource_id=str(user.id),
    )

    # In a production deployment this token would be emailed. For the
    # prototype we return it directly so the flow is testable without an
    # outbound mail provider configured.
    return RegisterResponse(
        message=(
            "Registration received. Verify your email using the token below "
            "(in production this is sent via email, not returned in the API response)."
            f" verification_token={raw_verification_token}"
        ),
        user_id=user.id,
        verification_required=True,
    )


@router.post("/verify-email", response_model=UserOut)
async def verify_email(payload: VerifyEmailRequest, db: AsyncSession = Depends(get_db)):
    try:
        user = await auth_service.verify_email(db, raw_token=payload.token)
    except auth_service.AuthError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message) from exc
    return user


@router.post("/login", response_model=TokenResponse)
@limiter.limit("10/minute")
async def login(request: Request, payload: LoginRequest, db: AsyncSession = Depends(get_db)):
    try:
        user = await auth_service.authenticate_user(db, email=payload.email, password=payload.password)
        access_token, refresh_token = await auth_service.issue_tokens(db, user)
    except auth_service.AuthError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message) from exc

    await record_audit_event(
        db, organization_id=user.organization_id, actor_user_id=user.id,
        action="user.login", resource_type="user", resource_id=str(user.id),
    )
    return TokenResponse(access_token=access_token, refresh_token=refresh_token)


@router.post("/refresh", response_model=TokenResponse)
async def refresh(payload: RefreshRequest, db: AsyncSession = Depends(get_db)):
    try:
        access_token, refresh_token = await auth_service.rotate_refresh_token(
            db, raw_refresh_token=payload.refresh_token
        )
    except auth_service.AuthError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message) from exc
    return TokenResponse(access_token=access_token, refresh_token=refresh_token)


@router.get("/me", response_model=UserOut)
async def me(current_user=Depends(get_current_user)):
    return current_user
