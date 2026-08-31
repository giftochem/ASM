"""Thin Celery wrapper -- mirrors app.tasks.scan_tasks/
discovery_schedule_tasks: real logic lives in
app.services.alert_delivery_executor, this only translates it into
Celery's task/retry semantics. The ONLY argument is a bare
notification_id UUID string -- no SMTP credentials or recipient
addresses ever cross the Celery broker (both are read fresh from
Settings/the database inside the worker, never passed as task
arguments).
"""

from celery.utils.log import get_task_logger

from app.celery_app import celery_app
from app.services import alert_delivery_executor

logger = get_task_logger(__name__)


@celery_app.task(bind=True, max_retries=3, default_retry_delay=60)
def deliver_alert_notification_task(self, notification_id: str) -> None:
    try:
        outcome = alert_delivery_executor.deliver(notification_id)
    except Exception as exc:
        logger.exception("deliver_alert_notification crashed for notification_id=%s, retrying", notification_id)
        raise self.retry(exc=exc)

    if outcome == "transient_failure":
        raise self.retry()
