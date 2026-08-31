"""Thin Celery wrapper. All real logic lives in app.services.scan_executor
— this module exists only to translate that logic into Celery's task/
retry semantics.
"""

from celery.utils.log import get_task_logger

from app.celery_app import celery_app
from app.services import scan_executor

logger = get_task_logger(__name__)


@celery_app.task(bind=True, max_retries=2, default_retry_delay=5)
def execute_scan_task(self, scan_id: str) -> None:
    try:
        scan_executor.execute_scan(scan_id)
    except Exception as exc:
        logger.exception("execute_scan failed for scan_id=%s, retrying", scan_id)
        raise self.retry(exc=exc)
