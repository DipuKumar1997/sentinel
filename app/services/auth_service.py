"""Registration / login / email-verification business logic.

Key identity rule enforced here: an organization is matched by the
*domain* of the registering user's email, not by free-text name entry
alone, so `alice@acme.com` cannot silently join an unrelated "Acme" org
created by someone else with a different domain.
"""
from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.organization import Organization, OrganizationStatus
from app.models.rbac import RoleName
from app.models.user import AccountStatus, EmailVerificationToken, RefreshToken, User
from app.security.passwords import hash_password, verify_password
from app.security.tokens import (
    create_access_token,
    generate_refresh_token,
    hash_refresh_token,
    refresh_token_expiry,
)


class AuthError(Exception):
    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


def _domain_of(email: str) -> str:
    return email.rsplit("@", 1)[-1].lower()


async def register_user(
    db: AsyncSession, *, full_name: str, email: str, password: str, organization_name: str
) -> tuple[User, str]:
    domain = _domain_of(email)

    existing_user = await db.scalar(select(User).where(User.email == email.lower()))
    if existing_user:
        raise AuthError("An account with this email already exists.", 409)

    org = await db.scalar(select(Organization).where(Organization.domain == domain))
    is_new_organization = org is None
    if org is None:
        org = Organization(
            name=organization_name,
            domain=domain,
            status=OrganizationStatus.PENDING,
            contact_email=email.lower(),
        )
        db.add(org)
        await db.flush()

    # The first person to register for a brand-new organization is
    # establishing that tenant, so they become its admin automatically
    # (there would otherwise be no path to ever reach org_admin -- see
    # CHANGELOG.md). Anyone joining an ALREADY-existing organization
    # (i.e. a colleague registering after the first person) gets the
    # baseline `employee` role; promoting them further is an org_admin
    # action, not a self-service one.
    initial_role = RoleName.ORG_ADMIN if is_new_organization else RoleName.EMPLOYEE

    user = User(
        organization_id=org.id,
        email=email.lower(),
        full_name=full_name,
        hashed_password=hash_password(password),
        role=initial_role,
        status=AccountStatus.PENDING_VERIFICATION,
        is_email_verified=False,
    )
    db.add(user)
    await db.flush()

    raw_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    verification = EmailVerificationToken(
        user_id=user.id,
        token_hash=token_hash,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
        used=False,
    )
    db.add(verification)

    await db.commit()
    await db.refresh(user)
    return user, raw_token


_MAX_FAILED_ATTEMPTS = 5
_LOCKOUT_MINUTES = 15


def _as_aware_utc(value: datetime) -> datetime:
    """SQLite (used in tests/dev) does not preserve tzinfo on DateTime
    columns; Postgres does. Normalize either case to an aware UTC datetime
    before comparison.
    """
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


async def verify_email(db: AsyncSession, *, raw_token: str) -> User:
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    verification = await db.scalar(
        select(EmailVerificationToken).where(EmailVerificationToken.token_hash == token_hash)
    )
    if verification is None or verification.used:
        raise AuthError("Invalid or already-used verification token.", 400)
    if _as_aware_utc(verification.expires_at) < datetime.now(timezone.utc):
        raise AuthError("Verification token has expired.", 400)

    user = await db.get(User, verification.user_id)
    if user is None:
        raise AuthError("User not found.", 404)

    user.is_email_verified = True
    user.status = AccountStatus.ACTIVE
    verification.used = True
    await db.commit()
    await db.refresh(user)
    return user


async def authenticate_user(db: AsyncSession, *, email: str, password: str) -> User:
    user = await db.scalar(select(User).where(User.email == email.lower()))
    if user is None:
        # Deliberately generic message and identical timing-shape path to
        # the "wrong password" branch below, to avoid account enumeration.
        raise AuthError("Incorrect email or password.", 401)

    if user.locked_until is not None and _as_aware_utc(user.locked_until) > datetime.now(timezone.utc):
        remaining_minutes = max(
            1, int((_as_aware_utc(user.locked_until) - datetime.now(timezone.utc)).total_seconds() // 60) + 1
        )
        raise AuthError(
            f"Account temporarily locked due to repeated failed login attempts. "
            f"Try again in about {remaining_minutes} minute(s).",
            423,
        )

    if not verify_password(password, user.hashed_password):
        user.failed_login_attempts += 1
        if user.failed_login_attempts >= _MAX_FAILED_ATTEMPTS:
            user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=_LOCKOUT_MINUTES)
        await db.commit()
        raise AuthError("Incorrect email or password.", 401)

    if user.status != AccountStatus.ACTIVE:
        raise AuthError(f"Account is {user.status.value}, not active.", 403)

    # Successful login: reset lockout bookkeeping.
    if user.failed_login_attempts or user.locked_until:
        user.failed_login_attempts = 0
        user.locked_until = None
        await db.commit()

    return user


async def issue_tokens(db: AsyncSession, user: User) -> tuple[str, str]:
    access_token = create_access_token(subject=str(user.id), extra_claims={"role": user.role.value})
    raw_refresh, refresh_hash = generate_refresh_token()
    db.add(
        RefreshToken(
            user_id=user.id,
            token_hash=refresh_hash,
            expires_at=refresh_token_expiry(),
            revoked=False,
        )
    )
    await db.commit()
    return access_token, raw_refresh


async def rotate_refresh_token(db: AsyncSession, *, raw_refresh_token: str) -> tuple[str, str]:
    token_hash = hash_refresh_token(raw_refresh_token)
    stored = await db.scalar(select(RefreshToken).where(RefreshToken.token_hash == token_hash))
    if stored is None or stored.revoked or _as_aware_utc(stored.expires_at) < datetime.now(timezone.utc):
        raise AuthError("Invalid or expired refresh token.", 401)

    user = await db.get(User, stored.user_id)
    if user is None or user.status != AccountStatus.ACTIVE:
        raise AuthError("Account is not active.", 403)

    stored.revoked = True  # rotate: old refresh token is single-use
    access_token, new_raw_refresh = await issue_tokens(db, user)
    return access_token, new_raw_refresh


async def is_reporter_registered(db: AsyncSession, *, email: str) -> bool:
    """Checks whether an email address belongs to a registered, active
    platform user -- used to decide between "create case" and "return
    registration/onboarding response" per the product requirement that
    the reporter's identity is verified independently of any address
    claimed inside the suspicious email itself.
    """
    user = await db.scalar(select(User).where(User.email == email.lower()))
    return user is not None and user.status == AccountStatus.ACTIVE
