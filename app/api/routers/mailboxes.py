"""Mailbox (forward-to-inbox) management: register a security mailbox,
enable/disable polling, and manually trigger a poll for immediate
testing/feedback without waiting for the scheduled sweep.

Restricted to org_admin+ -- registering a mailbox means storing IMAP
credentials (encrypted) for that inbox, a privileged action.
"""
import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.models.case import Mailbox
from app.models.rbac import RoleName
from app.models.user import User
from app.schemas.mailbox import CreateMailboxRequest, MailboxOut, PollNowResponse, PollOutcomeOut
from app.security.rbac import require_min_role
from app.services import mailbox_polling, mailbox_service
from app.services.audit import record_audit_event

router = APIRouter(prefix="/mailboxes", tags=["mailboxes"])


@router.post("", response_model=MailboxOut, status_code=status.HTTP_201_CREATED)
async def create_mailbox(
    payload: CreateMailboxRequest,
    current_user: User = Depends(require_min_role(RoleName.ORG_ADMIN)),
    db: AsyncSession = Depends(get_db),
):
    try:
        mailbox = await mailbox_service.create_mailbox(
            db,
            organization_id=current_user.organization_id,
            address=payload.address,
            description=payload.description,
            imap_host=payload.imap_host,
            imap_port=payload.imap_port,
            imap_use_ssl=payload.imap_use_ssl,
            imap_username=payload.imap_username,
            imap_password=payload.imap_password,
            imap_folder=payload.imap_folder,
            smtp_host=payload.smtp_host,
            smtp_port=payload.smtp_port,
            smtp_use_tls=payload.smtp_use_tls,
            notify_reporter=payload.notify_reporter,
        )
    except mailbox_service.MailboxError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message) from exc

    await record_audit_event(
        db, organization_id=current_user.organization_id, actor_user_id=current_user.id,
        action="mailbox.create", resource_type="mailbox", resource_id=str(mailbox.id),
        detail={"address": mailbox.address},
    )
    return mailbox


@router.get("", response_model=list[MailboxOut])
async def list_mailboxes(
    current_user: User = Depends(require_min_role(RoleName.ORG_ADMIN)),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Mailbox).where(Mailbox.organization_id == current_user.organization_id).order_by(Mailbox.created_at.desc())
    )
    return result.scalars().all()


async def _get_org_mailbox(db: AsyncSession, mailbox_id: uuid.UUID, organization_id: uuid.UUID) -> Mailbox:
    mailbox = await db.get(Mailbox, mailbox_id)
    if mailbox is None or mailbox.organization_id != organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Mailbox not found.")
    return mailbox


@router.patch("/{mailbox_id}/enable", response_model=MailboxOut)
async def enable_polling(
    mailbox_id: uuid.UUID,
    current_user: User = Depends(require_min_role(RoleName.ORG_ADMIN)),
    db: AsyncSession = Depends(get_db),
):
    mailbox = await _get_org_mailbox(db, mailbox_id, current_user.organization_id)
    return await mailbox_service.set_polling_enabled(db, mailbox=mailbox, enabled=True)


@router.patch("/{mailbox_id}/disable", response_model=MailboxOut)
async def disable_polling(
    mailbox_id: uuid.UUID,
    current_user: User = Depends(require_min_role(RoleName.ORG_ADMIN)),
    db: AsyncSession = Depends(get_db),
):
    mailbox = await _get_org_mailbox(db, mailbox_id, current_user.organization_id)
    return await mailbox_service.set_polling_enabled(db, mailbox=mailbox, enabled=False)


@router.delete("/{mailbox_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_mailbox(
    mailbox_id: uuid.UUID,
    current_user: User = Depends(require_min_role(RoleName.ORG_ADMIN)),
    db: AsyncSession = Depends(get_db),
):
    mailbox = await _get_org_mailbox(db, mailbox_id, current_user.organization_id)
    await mailbox_service.delete_mailbox(db, mailbox=mailbox)
    await record_audit_event(
        db, organization_id=current_user.organization_id, actor_user_id=current_user.id,
        action="mailbox.delete", resource_type="mailbox", resource_id=str(mailbox_id),
    )


@router.post("/{mailbox_id}/poll-now", response_model=PollNowResponse)
async def poll_now(
    mailbox_id: uuid.UUID,
    current_user: User = Depends(require_min_role(RoleName.ORG_ADMIN)),
    db: AsyncSession = Depends(get_db),
):
    """Synchronously polls this mailbox right now, rather than waiting
    for the scheduled Celery beat sweep -- useful for verifying your
    IMAP credentials/forwarding setup actually works end to end.
    """
    mailbox = await _get_org_mailbox(db, mailbox_id, current_user.organization_id)
    outcomes = await mailbox_polling.poll_mailbox(db, mailbox)

    await record_audit_event(
        db, organization_id=current_user.organization_id, actor_user_id=current_user.id,
        action="mailbox.poll_now", resource_type="mailbox", resource_id=str(mailbox_id),
        detail={"outcomes_count": len(outcomes)},
    )

    if mailbox.last_poll_status == "error" and not outcomes:
        message = f"Poll failed: {mailbox.last_poll_error}"
    elif not outcomes:
        message = "Poll succeeded -- no new messages found."
    else:
        created = sum(1 for o in outcomes if o.status == "created")
        message = f"Poll succeeded -- {created} new case(s) created out of {len(outcomes)} message(s) seen."

    return PollNowResponse(
        mailbox_id=mailbox_id,
        outcomes=[PollOutcomeOut(uid=o.uid, status=o.status, case_id=o.case_id, detail=o.detail) for o in outcomes],
        message=message,
    )
