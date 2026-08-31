from celery import Celery

from app.config import settings

celery_app = Celery("asm", broker=settings.redis_url, backend=settings.redis_url)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    task_track_started=True,
    # Defaults to real async execution everywhere, tests included. Eager
    # mode (synchronous, in-process, no broker needed) is opt-in per test
    # via the `eager_celery` fixture, not a global default anything can
    # quietly depend on — see tests/conftest.py.
    task_always_eager=settings.celery_task_always_eager,
    task_eager_propagates=True,
    # Step 9.11: the ONLY periodic task in this project -- a fixed,
    # short interval (not a configurable cron expression; arbitrary
    # cron is an explicit non-goal for this pass). Requires a `celery -A
    # app.celery_app beat` process running alongside the worker (see the
    # `beat` service in docker-compose.yml) -- Beat itself only ever
    # enqueues this one lightweight dispatch task; it never executes a
    # provider directly.
    beat_schedule={
        "dispatch-due-discovery-schedules": {
            "task": "app.tasks.discovery_schedule_tasks.dispatch_due_discovery_schedules",
            "schedule": 60.0,
        },
    },
)

# autodiscover_tasks(["app.tasks"]) would look for an app.tasks.tasks
# module (Django-app-style convention) — our tasks live in
# app.tasks.scan_tasks/discovery_schedule_tasks/alert_notification_tasks,
# so they're imported explicitly instead. These imports are what
# actually register @celery_app.task-decorated functions; they must
# stay below the Celery app + conf setup above (each task module
# imports `from app.celery_app import celery_app`, so importing them
# earlier would be a circular import).
from app.tasks import alert_notification_tasks, discovery_schedule_tasks, scan_tasks  # noqa: E402,F401
