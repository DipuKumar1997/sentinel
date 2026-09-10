"""Celery tasks. Celery workers call plain synchronous functions, but
our polling logic is async (it shares the same async DB session/engine
as the rest of the app) -- each task creates its own short-lived event
loop and DB session, runs the async logic to completion, and returns.
"""
from __future__ import annotations

import asyncio

from app.db.session import AsyncSessionLocal
from app.services import mailbox_polling
from app.workers.celery_app import celery_app


async def _poll_all_mailboxes_async() -> dict:
    async with AsyncSessionLocal() as db:
        results = await mailbox_polling.poll_all_active_mailboxes(db)
    return {
        str(mailbox_id): [
            {"uid": o.uid, "status": o.status, "case_id": str(o.case_id) if o.case_id else None}
            for o in outcomes
        ]
        for mailbox_id, outcomes in results.items()
    }


@celery_app.task(name="app.workers.tasks.poll_all_mailboxes_task")
def poll_all_mailboxes_task() -> dict:
    return asyncio.run(_poll_all_mailboxes_async())


async def _poll_one_mailbox_async(mailbox_id: str) -> list[dict]:
    import uuid as uuid_module

    from app.models.case import Mailbox

    async with AsyncSessionLocal() as db:
        mailbox = await db.get(Mailbox, uuid_module.UUID(mailbox_id))
        if mailbox is None:
            return []
        outcomes = await mailbox_polling.poll_mailbox(db, mailbox)
        return [
            {"uid": o.uid, "status": o.status, "case_id": str(o.case_id) if o.case_id else None}
            for o in outcomes
        ]


@celery_app.task(name="app.workers.tasks.poll_one_mailbox_task")
def poll_one_mailbox_task(mailbox_id: str) -> list[dict]:
    return asyncio.run(_poll_one_mailbox_async(mailbox_id))
