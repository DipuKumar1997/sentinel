"""Mailbox (forward-to-inbox) management: creating/updating/listing the
security mailboxes an organization forwards suspicious mail to, and the
dedicated service-account user each one is attributed to.
"""
from __future__ import annotations

import secrets
import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.case import Mailbox
from app.models.rbac import RoleName
from app.models.user import AccountStatus, User
from app.security.passwords import hash_password
from app.security.secret_encryption import decrypt_secret, encrypt_secret


class MailboxError(Exception):
    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


async def create_mailbox(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    address: str,
    description: str | None,
    imap_host: str,
    imap_port: int,
    imap_use_ssl: bool,
    imap_username: str,
    imap_password: str,
    imap_folder: str = "Sentinel_Intake",
    smtp_host: str | None = None,
    smtp_port: int = 587,
    smtp_use_tls: bool = True,
    notify_reporter: bool = True,
) -> Mailbox:
    existing = await db.scalar(select(Mailbox).where(Mailbox.address == address.lower()))
    if existing:
        raise MailboxError("A mailbox with this address is already registered.", 409)

    service_user = User(
        organization_id=organization_id,
        email=f"mailbox-{uuid.uuid4().hex[:12]}@service.internal",
        full_name=f"Mailbox intake: {address}",
        hashed_password=hash_password(secrets.token_urlsafe(32)),
        role=RoleName.EMPLOYEE,
        status=AccountStatus.ACTIVE,
        is_email_verified=True,
    )
    db.add(service_user)
    await db.flush()

    mailbox = Mailbox(
        organization_id=organization_id,
        address=address.lower(),
        description=description,
        is_active=True,
        imap_host=imap_host,
        imap_port=imap_port,
        imap_use_ssl=imap_use_ssl,
        imap_username=imap_username,
        encrypted_password=encrypt_secret(imap_password),
        imap_folder=imap_folder,
        is_polling_enabled=True,
        service_user_id=service_user.id,
        smtp_host=smtp_host,
        smtp_port=smtp_port,
        smtp_use_tls=smtp_use_tls,
        notify_reporter=notify_reporter,
    )
    db.add(mailbox)
    await db.commit()
    await db.refresh(mailbox)
    return mailbox


def get_decrypted_password(mailbox: Mailbox) -> str:
    if not mailbox.encrypted_password:
        raise MailboxError("Mailbox has no stored IMAP credentials.", 400)
    return decrypt_secret(mailbox.encrypted_password)


async def set_polling_enabled(db: AsyncSession, *, mailbox: Mailbox, enabled: bool) -> Mailbox:
    mailbox.is_polling_enabled = enabled
    await db.commit()
    await db.refresh(mailbox)
    return mailbox


async def delete_mailbox(db: AsyncSession, *, mailbox: Mailbox) -> None:
    await db.delete(mailbox)
    await db.commit()
