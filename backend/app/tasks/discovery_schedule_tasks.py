"""Thin Celery wrappers for scheduled discovery (Step 9.11). All real
logic lives in app.services.discovery_scheduler_executor -- these
modules exist only to translate that logic into Celery's task/retry/
periodic-schedule semantics, exactly mirroring app.tasks.scan_tasks.
"""

from celery.utils.log import get_task_logger

from app import database
from app.celery_app import celery_app
from app.services import discovery_scheduler_executor

logger = get_task_logger(__name__)

# Hard/soft time limits bound how long a single scheduled provider
# execution may occupy a worker -- provider-level timeouts already
# exist (e.g. DNS/HTTP connect/read timeouts), but this is the
# orchestration-level backstop Step 9.11.5 requires: even a provider
# that somehow ignores its own internal timeout cannot occupy a worker
# forever. soft_time_limit raises a catchable SoftTimeLimitExceeded
# inside the task first; time_limit is the hard SIGKILL a few seconds
# later if that doesn't clean up in time -- reap_stale_runs (run at the
# top of every dispatch tick) is the backstop for that hard-kill case,
# where no Python cleanup code gets a chance to run at all.
EXECUTION_SOFT_TIME_LIMIT_SECONDS = 270
EXECUTION_TIME_LIMIT_SECONDS = 300


@celery_app.task
def dispatch_due_discovery_schedules() -> int:
    """The Celery Beat-triggered periodic task (see celery_app.py's
    beat_schedule) -- runs frequently (every 60s), stays cheap: reap
    anything stuck, claim what's due, hand each claimed run off to its
    own execution task. Returns the number of runs dispatched (useful
    for tests/observability, not consumed by anything else).
    """
    db = database.SessionLocal()
    try:
        discovery_scheduler_executor.reap_stale_runs(db)
        runs = discovery_scheduler_executor.claim_due_schedules(db)
        for run in runs:
            execute_scheduled_discovery_task.delay(str(run.id), str(run.schedule_id))
        return len(runs)
    finally:
        db.close()


@celery_app.task(bind=True, max_retries=2, default_retry_delay=30, soft_time_limit=EXECUTION_SOFT_TIME_LIMIT_SECONDS, time_limit=EXECUTION_TIME_LIMIT_SECONDS)
def execute_scheduled_discovery_task(self, run_id: str, schedule_id: str) -> None:
    try:
        discovery_scheduler_executor.execute_scheduled_run(run_id, schedule_id)
    except Exception as exc:
        logger.exception("execute_scheduled_run failed for run_id=%s schedule_id=%s, retrying", run_id, schedule_id)
        raise self.retry(exc=exc)
