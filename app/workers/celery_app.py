"""Celery application instance.

Not yet used by the ingestion pipeline in this checkpoint (ingestion runs
synchronously within the request for simplicity/testability -- see
docs/architecture.md). Scaffolded so moving heavy analysis work off the
request path later is a matter of wrapping existing pure functions in a
`@celery_app.task`, not a redesign.
"""
from celery import Celery

from app.core.config import settings

celery_app = Celery(
    "sentinelmail",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
)
