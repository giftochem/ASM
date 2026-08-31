"""Worker-facing half of scheduled discovery (Step 9.11) -- runs inside
a Celery worker, never inside an HTTP request. Mirrors
app.services.scan_executor's shape closely: opens its own DB session,
re-validates authorization immediately before doing any work (the one
check that can't go stale, since real time passes between a schedule
being created and a worker actually picking it up hours or days
later), and uses atomic conditional UPDATEs -- never "read status in
Python, then write" -- as the sole concurrency-safety mechanism,
exactly like scan_executor's proven queued->running transition.

CONCURRENCY MODEL: claiming (this module's own job) and executing (a
thin hand-off to the existing, unmodified discovery_service.execute_run)
are deliberately two different atomicity boundaries:
  1. `claim_due_schedules`/`claim_schedule_now` claim the SCHEDULE
     (via `SELECT ... FOR UPDATE SKIP LOCKED` for a batch, or a single
     atomic conditional UPDATE for one) and create the DiscoveryRun for
     that attempt in the same transaction -- this is what prevents a
     schedule from getting a second concurrent run.
  2. `execute_scheduled_run` additionally claims the RUN itself (atomic
     `UPDATE ... WHERE status = 'queued'`) before calling
     discovery_service.execute_run -- this is what prevents the exact
     same run from being executed twice if its dispatch message is
     ever redelivered (a real possibility under most Celery broker
     configurations, independent of anything schedule-level).
Both are plain Postgres transactional guarantees; no distributed lock
of any kind is used.

AUTHORIZATION MODEL: Asset.authorization_confirmed already IS persisted,
revocable authorization -- there is no second authorization concept to
invent here. What changes for scheduled execution is *when* it gets
re-checked: exactly like scan_executor re-validates immediately before
running any scanner module (not trusting the check scan_service did at
creation time), this module re-validates via the exact same
discovery_service.validate_discovery_request immediately before
executing any provider -- never relying on whatever was true when the
schedule was created. A schedule whose seed is no longer authorized (or
whose asset was deactivated) is auto-disabled, not merely failed once,
so it stops firing repeatedly against something it's no longer allowed
to touch -- "a revoked authorization must prevent FUTURE execution."
"""

import logging
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import or_, update
from sqlalchemy.orm import Session

from app import database
from app.core.enums import DiscoveryRunStatus
from app.core.exceptions import AuthorizationNotConfirmedError
from app.discovery.registry import get_provider
from app.models.asset import Asset
from app.models.discovery_run import DiscoveryRun
from app.models.discovery_schedule import DiscoverySchedule
from app.models.user import User
from app.services import alert_service, discovery_service

logger = logging.getLogger(__name__)

# Generously longer than the Celery task's own hard time_limit (see
# app/tasks/discovery_schedule_tasks.py) -- a claim/run only counts as
# "stale" (worker crashed, or was killed by Celery's own limit, before
# it could clean up after itself) well after a legitimate execution
# would already have finished on its own.
STALE_CLAIM_TIMEOUT = timedelta(minutes=10)
DEFAULT_CLAIM_BATCH_SIZE = 50


def reap_stale_runs(db: Session) -> int:
    """Sweeps DiscoveryRuns stuck in `running` past STALE_CLAIM_TIMEOUT
    -- a worker crashed or was hard-killed by Celery's own time limit
    before it could mark the run itself failed. ALWAYS marks these
    `failed`, never `completed` -- and critically, never calls
    detect_and_mark_disappeared_candidates for one (that only ever
    happens on discovery_service.execute_run's own successful-
    completion path, which a reaped run never reached) -- Step 9.9's
    "a failed run must never trigger disappearance detection" safety
    semantics are preserved by simply not touching that code path at
    all here.

    Also releases the owning schedule's claim so it becomes claimable
    again on the very next dispatch tick, rather than waiting out the
    rest of its interval.
    """
    stale_cutoff = datetime.now(timezone.utc) - STALE_CLAIM_TIMEOUT
    stuck_runs = (
        db.query(DiscoveryRun)
        .filter(DiscoveryRun.status == DiscoveryRunStatus.running, DiscoveryRun.started_at < stale_cutoff)
        .all()
    )
    for run in stuck_runs:
        run.status = DiscoveryRunStatus.failed
        run.error_message = "Execution timed out or the worker did not report completion (reaped by the scheduler)"
        run.completed_at = datetime.now(timezone.utc)
        if run.schedule_id is not None:
            schedule = db.get(DiscoverySchedule, run.schedule_id)
            if schedule is not None:
                schedule.claimed_at = None
    db.commit()
    return len(stuck_runs)


def claim_due_schedules(db: Session, batch_size: int = DEFAULT_CLAIM_BATCH_SIZE) -> list[DiscoveryRun]:
    """The dispatcher's own job: atomically claim a batch of due,
    enabled, not-currently-claimed (or stale-claimed) schedules and
    create the DiscoveryRun for each attempt, all in one transaction.
    `FOR UPDATE SKIP LOCKED` is the textbook PostgreSQL pattern for
    exactly this "hand out independent units of work across concurrent
    workers" shape: a row already locked by a concurrent claim (another
    dispatch tick still in flight, vanishingly unlikely with a single
    Beat process but not assumed away) is silently skipped rather than
    blocked on or double-claimed.

    Returns the newly created DiscoveryRuns -- the caller (the Celery
    task) is responsible for dispatching one execution task per run.
    """
    now = datetime.now(timezone.utc)
    stale_cutoff = now - STALE_CLAIM_TIMEOUT

    due_schedules = (
        db.query(DiscoverySchedule)
        .filter(
            DiscoverySchedule.enabled.is_(True),
            DiscoverySchedule.next_run_at <= now,
            or_(DiscoverySchedule.claimed_at.is_(None), DiscoverySchedule.claimed_at < stale_cutoff),
        )
        .order_by(DiscoverySchedule.next_run_at)
        .limit(batch_size)
        .with_for_update(skip_locked=True)
        .all()
    )

    if not due_schedules:
        return []

    # Batched, not one query per schedule: every owner this batch could
    # possibly need is fetched in a single IN() query up front.
    owner_ids = {schedule.created_by for schedule in due_schedules}
    active_owner_ids = {
        row[0] for row in db.query(User.id).filter(User.id.in_(owner_ids), User.is_active.is_(True)).all()
    }

    created_runs: list[DiscoveryRun] = []
    for schedule in due_schedules:
        if schedule.created_by not in active_owner_ids:
            # Permanent problem, not a transient one -- stop retrying.
            schedule.enabled = False
            schedule.disabled_reason = "Schedule owner no longer exists or is inactive"
            continue

        run = DiscoveryRun(
            organization_id=schedule.organization_id,
            seed_asset_id=schedule.seed_asset_id,
            initiated_by=schedule.created_by,
            provider_name=schedule.provider_name,
            status=DiscoveryRunStatus.queued,
            schedule_id=schedule.id,
        )
        db.add(run)
        schedule.claimed_at = now
        created_runs.append(run)

    db.commit()
    # No per-row refresh: `id` is a client-side default (uuid.uuid4,
    # evaluated in Python before INSERT) and `schedule_id` was set
    # explicitly above, so both are already correct on each object --
    # only server-computed columns (created_at/updated_at) would need a
    # refresh, and nothing this function's caller does needs those.
    return created_runs


def claim_schedule_now(db: Session, schedule: DiscoverySchedule) -> DiscoveryRun | None:
    """Manual trigger (Step 9.11.8) -- claims regardless of
    `next_run_at` timing, but still enforces the identical "not already
    claimed and running" guarantee the dispatcher's batch claim does,
    via a single atomic conditional UPDATE (the one-row equivalent of
    claim_due_schedules' `SKIP LOCKED` batch claim). Returns None if a
    run is already in progress for this schedule -- the route turns
    that into a 409, never silently queuing a second concurrent run.
    """
    now = datetime.now(timezone.utc)
    stale_cutoff = now - STALE_CLAIM_TIMEOUT

    result = db.execute(
        update(DiscoverySchedule)
        .where(
            DiscoverySchedule.id == schedule.id,
            DiscoverySchedule.enabled.is_(True),
            or_(DiscoverySchedule.claimed_at.is_(None), DiscoverySchedule.claimed_at < stale_cutoff),
        )
        .values(claimed_at=now)
    )
    if result.rowcount == 0:
        db.commit()
        return None

    run = DiscoveryRun(
        organization_id=schedule.organization_id,
        seed_asset_id=schedule.seed_asset_id,
        initiated_by=schedule.created_by,
        provider_name=schedule.provider_name,
        status=DiscoveryRunStatus.queued,
        schedule_id=schedule.id,
    )
    db.add(run)
    db.commit()
    db.refresh(run)
    return run


def _dependency_satisfied(db: Session, seed_asset: Asset, depends_on: set[str]) -> bool:
    """Step 9.11.6 -- the smallest useful dependency mechanism: a plain
    existence check for at least one prior SUCCESSFUL run of a
    depended-on provider against this exact seed. Not a live blocking
    gate on some other schedule currently running, not a DAG, no
    transitive resolution -- "has the upstream intelligence this
    provider benefits from ever actually been collected."
    """
    return (
        db.query(DiscoveryRun)
        .filter(
            DiscoveryRun.seed_asset_id == seed_asset.id,
            DiscoveryRun.provider_name.in_(depends_on),
            DiscoveryRun.status == DiscoveryRunStatus.completed,
        )
        .first()
        is not None
    )


def _release_and_finish(
    db: Session, run: DiscoveryRun, schedule: DiscoverySchedule, *, disable: bool, reason: str
) -> None:
    schedule.claimed_at = None
    schedule.last_run_at = datetime.now(timezone.utc)
    schedule.last_run_id = run.id
    if disable:
        schedule.enabled = False
        schedule.disabled_reason = reason
    else:
        schedule.next_run_at = datetime.now(timezone.utc) + timedelta(hours=schedule.interval_hours)
    db.commit()


def _alert_authorization_disabled(
    db: Session, seed_asset: Asset, schedule: DiscoverySchedule, run: DiscoveryRun, reason: str
) -> None:
    """Step 9.12: the one alert type not sourced from an Observation --
    see app.services.alert_service's module docstring. Wrapped in
    try/except so a bug in alerting can never affect the scheduler's
    own (already-committed, via _release_and_finish above) failure
    handling -- schedule/run state is correct either way.
    """
    try:
        alert_service.create_authorization_disabled_alert(db, seed_asset, schedule, run, reason)
    except Exception:
        logger.exception("failed to create authorization_disabled alert for schedule_id=%s", schedule.id)


def execute_scheduled_run(run_id: uuid.UUID | str, schedule_id: uuid.UUID | str) -> None:
    """The actual worker-side entry point, invoked by
    app.tasks.discovery_schedule_tasks.execute_scheduled_discovery_task.
    Opens its own session via `database.SessionLocal` looked up as a
    module attribute (not `from app.database import SessionLocal`) --
    the exact same reason scan_executor.execute_scan does this: a
    plain import binds a frozen reference at import time that tests
    couldn't monkeypatch to redirect at the test database (see
    `executor_uses_test_db` in tests/conftest.py).
    """
    db = database.SessionLocal()
    try:
        run = db.get(DiscoveryRun, uuid.UUID(str(run_id)))
        schedule = db.get(DiscoverySchedule, uuid.UUID(str(schedule_id)))
        if run is None or schedule is None:
            return

        # Atomic conditional transition -- prevents this exact run from
        # ever being executed twice (a redelivered/duplicate dispatch
        # message is a real possibility independent of schedule-level
        # claiming). Mirrors scan_executor.execute_scan's identical
        # queued->running guard precisely.
        result = db.execute(
            update(DiscoveryRun)
            .where(DiscoveryRun.id == run.id, DiscoveryRun.status == DiscoveryRunStatus.queued)
            .values(status=DiscoveryRunStatus.running, started_at=datetime.now(timezone.utc))
        )
        db.commit()
        if result.rowcount == 0:
            return
        db.refresh(run)

        seed_asset = db.get(Asset, run.seed_asset_id)

        provider = get_provider(run.provider_name)
        if provider is not None and provider.depends_on and seed_asset is not None:
            if not _dependency_satisfied(db, seed_asset, provider.depends_on):
                run.status = DiscoveryRunStatus.cancelled
                run.error_message = (
                    f"Skipped: prerequisite provider(s) {sorted(provider.depends_on)} have not yet "
                    "completed successfully for this asset"
                )
                run.completed_at = datetime.now(timezone.utc)
                # Released immediately, not disabled -- this is a
                # transient, self-resolving condition (the very next
                # tick retries) rather than a permanent problem.
                schedule.claimed_at = None
                db.commit()
                return

        if seed_asset is None or not seed_asset.is_active or not seed_asset.authorization_confirmed:
            run.status = DiscoveryRunStatus.failed
            run.error_message = "Authorization was revoked, or the asset was deactivated, before scheduled execution"
            run.completed_at = datetime.now(timezone.utc)
            _release_and_finish(db, run, schedule, disable=True, reason=run.error_message)
            if seed_asset is not None:
                _alert_authorization_disabled(db, seed_asset, schedule, run, run.error_message)
            return

        try:
            resolved_provider = discovery_service.validate_discovery_request(seed_asset, run.provider_name)
        except AuthorizationNotConfirmedError as exc:
            run.status = DiscoveryRunStatus.failed
            run.error_message = str(exc)
            run.completed_at = datetime.now(timezone.utc)
            _release_and_finish(db, run, schedule, disable=True, reason=str(exc))
            _alert_authorization_disabled(db, seed_asset, schedule, run, str(exc))
            return
        except ValueError as exc:
            # A permanent configuration problem (provider no longer
            # registered, or no longer supports this asset_type) --
            # distinct from an authorization failure, but equally not
            # worth retrying forever.
            run.status = DiscoveryRunStatus.failed
            run.error_message = str(exc)
            run.completed_at = datetime.now(timezone.utc)
            _release_and_finish(
                db, run, schedule, disable=True, reason=f"Schedule configuration is no longer valid: {exc}"
            )
            return

        discovery_service.execute_run(db, run, resolved_provider, seed_asset)
        db.refresh(run)
        _release_and_finish(db, run, schedule, disable=False, reason="")
    except Exception:
        # Defense in depth: an unexpected exception anywhere above must
        # not leave the run stuck in `running` or the schedule
        # permanently claimed. Marked failed and released here; the
        # Celery task wrapper still sees this re-raised and applies its
        # own retry policy on top.
        db.rollback()
        run = db.get(DiscoveryRun, uuid.UUID(str(run_id)))
        schedule = db.get(DiscoverySchedule, uuid.UUID(str(schedule_id)))
        if run is not None and run.status == DiscoveryRunStatus.running:
            run.status = DiscoveryRunStatus.failed
            run.error_message = "Unexpected error during scheduled execution"
            run.completed_at = datetime.now(timezone.utc)
        if schedule is not None:
            schedule.claimed_at = None
        db.commit()
        raise
    finally:
        db.close()
