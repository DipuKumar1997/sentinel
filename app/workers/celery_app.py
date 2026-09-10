"""Celery application instance.

Runs the scheduled mailbox-polling sweep (see
app/services/mailbox_polling.py and app/workers/tasks.py) -- the
background, no-human-in-the-loop "forward to security@company.com"
intake mode. Interactive uploads (dashboard/API/API-key) still run
their analysis synchronously within the request path (see
docs/architecture.md); Celery is used here specifically because
mailbox polling has no request to respond to.
"""
from celery import Celery

from app.core.config import settings

celery_app = Celery(
    "sentinelmail",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
    include=["app.workers.tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
)

# Sweep every active, polling-enabled mailbox every 2 minutes. Real-world
# forwarding latency is dominated by IMAP polling interval, not analysis
# time (which is sub-second) -- 2 minutes is a reasonable default for a
# "forward a suspicious email, get a case shortly after" experience
# without hammering the mail provider's rate limits.
celery_app.conf.beat_schedule = {
    "poll-all-mailboxes-every-2-minutes": {
        "task": "app.workers.tasks.poll_all_mailboxes_task",
        "schedule": 120.0,
    },
}
