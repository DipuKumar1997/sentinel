"""Celery tasks. Celery workers call plain synchronous functions, but
our polling logic is async (it shares the same async DB session/engine
as the rest of the app) -- each task creates its own short-lived event
loop and DB session, runs the async logic to completion, and returns.
"""
from __future__ import annotations

import asyncio
import logging

from app.db.session import AsyncSessionLocal, engine
from app.services import mailbox_polling
from app.workers.celery_app import celery_app

logger = logging.getLogger(__name__)


async def _poll_all_mailboxes_async() -> dict:
    try:
        async with AsyncSessionLocal() as db:
            try:
                results = await mailbox_polling.poll_all_active_mailboxes(db)
                await db.commit()
            except Exception:
                await db.rollback()
                raise

        return {
            str(mailbox_id): [
                {
                    "uid": o.uid,
                    "status": o.status,
                    "case_id": str(o.case_id) if o.case_id else None,
                }
                for o in outcomes
            ]
            for mailbox_id, outcomes in results.items()
        }
    finally:
        # CRITICAL FIX: Dispose of the engine to clear the asyncpg connection pool.
        # This prevents "Event loop is closed" errors on subsequent Celery runs.
        await engine.dispose()


@celery_app.task(
    name="app.workers.tasks.poll_all_mailboxes_task",
    bind=True,
)
def poll_all_mailboxes_task(self) -> dict:
    try:
        return asyncio.run(_poll_all_mailboxes_async())
    except Exception:
        logger.exception(
            "Mailbox polling task failed. task_id=%s",
            self.request.id,
        )
        raise


async def _poll_one_mailbox_async(mailbox_id: str) -> list[dict]:
    import uuid as uuid_module
    from app.models.case import Mailbox

    try:
        async with AsyncSessionLocal() as db:
            try:
                mailbox = await db.get(
                    Mailbox,
                    uuid_module.UUID(mailbox_id),
                )

                if mailbox is None:
                    return []

                outcomes = await mailbox_polling.poll_mailbox(
                    db,
                    mailbox,
                )

                await db.commit()

                return [
                    {
                        "uid": o.uid,
                        "status": o.status,
                        "case_id": str(o.case_id) if o.case_id else None,
                    }
                    for o in outcomes
                ]

            except Exception:
                await db.rollback()
                raise
    finally:
        # CRITICAL FIX: Dispose of the engine
        await engine.dispose()


@celery_app.task(
    name="app.workers.tasks.poll_one_mailbox_task",
    bind=True,
)
def poll_one_mailbox_task(self, mailbox_id: str) -> list[dict]:
    try:
        return asyncio.run(_poll_one_mailbox_async(mailbox_id))
    except Exception:
        logger.exception(
            "Mailbox polling failed for mailbox_id=%s task_id=%s",
            mailbox_id,
            self.request.id,
        )
        raise
