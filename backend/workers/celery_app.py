"""Celery application configuration."""

from celery import Celery
from celery.schedules import crontab

from backend.core.config import settings

# Create Celery app
celery_app = Celery(
    "pentest_automation",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
    include=["backend.workers.tasks"]
)

# Celery configuration
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=settings.SCAN_TIMEOUT,
    worker_prefetch_multiplier=1,
    worker_max_tasks_per_child=1000,
)

# Periodic tasks
celery_app.conf.beat_schedule = {
    "cleanup-old-scans": {
        "task": "backend.workers.tasks.cleanup_old_scans",
        "schedule": crontab(hour=2, minute=0),  # Run daily at 2 AM
    },
    "check-scheduled-scans": {
        "task": "backend.workers.tasks.check_scheduled_scans",
        "schedule": crontab(minute="*/5"),  # Run every 5 minutes
    },
}

if __name__ == "__main__":
    celery_app.start()
