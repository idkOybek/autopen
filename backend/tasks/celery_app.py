"""
Celery application configuration for pentest automation.
"""

from celery import Celery
from celery.schedules import crontab

from backend.core.config import settings

# Initialize Celery app
celery_app = Celery(
    "pentest_automation",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
)

# Celery configuration
celery_app.conf.update(
    # Serialization settings
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",

    # Timezone settings
    timezone="UTC",
    enable_utc=True,

    # Task execution settings
    task_track_started=True,
    task_time_limit=7200,  # 2 hours max
    task_soft_time_limit=6900,  # 1h 55min soft limit
    task_acks_late=True,  # Acknowledge after task completion
    task_reject_on_worker_lost=True,  # Reject tasks if worker crashes

    # Worker settings
    worker_prefetch_multiplier=1,  # Don't prefetch tasks
    worker_max_tasks_per_child=50,  # Restart worker after 50 tasks to prevent memory leaks
    worker_disable_rate_limits=False,

    # Result backend settings
    result_expires=86400,  # Results expire after 24 hours
    result_backend_transport_options={
        "master_name": "mymaster",
    },

    # Task routing
    task_routes={
        "backend.tasks.scan_tasks.scan_single_target": {"queue": "scans"},
        "backend.tasks.scan_tasks.process_targets": {"queue": "processing"},
        "backend.tasks.scan_tasks.generate_final_reports": {"queue": "reports"},
        "backend.tasks.scan_tasks.update_tools": {"queue": "maintenance"},
        "backend.tasks.scan_tasks.cleanup_old_scans": {"queue": "maintenance"},
    },

    # Beat schedule for periodic tasks
    beat_schedule={
        "update-tools-daily": {
            "task": "backend.tasks.scan_tasks.update_tools",
            "schedule": crontab(hour=3, minute=0),  # 3:00 AM UTC
        },
        "cleanup-old-scans": {
            "task": "backend.tasks.scan_tasks.cleanup_old_scans",
            "schedule": crontab(hour=4, minute=0),  # 4:00 AM UTC
            "kwargs": {"days": 30},
        },
    },
)

# Auto-discover tasks from all apps
celery_app.autodiscover_tasks(["backend.tasks"])


# Task configuration decorator
def configured_task(**kwargs):
    """
    Decorator for tasks with default configuration.
    """
    defaults = {
        "bind": True,
        "max_retries": 3,
        "autoretry_for": (Exception,),
        "retry_backoff": True,
        "retry_backoff_max": 600,  # 10 minutes max backoff
        "retry_jitter": True,
    }
    defaults.update(kwargs)
    return celery_app.task(**defaults)
