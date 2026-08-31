"""Tests for discovery_scheduler_executor's execution semantics:
successful background execution, provider exceptions, authorization
revoked before execution, dependency handling, zero-result runs,
next-run calculation, stale-run reaping, and disappearance-detection
safety -- all against the real (test) database, calling the worker-side
functions directly (mirroring how test_scan_race_safety.py calls
scan_executor.execute_scan directly rather than only through Celery).
"""

import uuid
from datetime import datetime, timedelta, timezone

import pytest

from app.core.enums import AssetType, DiscoveryRunStatus, LifecycleStatus
from app.discovery.registry import DISCOVERY_PROVIDER_REGISTRY
from app.models.asset import Asset
from app.models.asset_relationship import AssetRelationship
from app.models.discovery_run import DiscoveryRun
from app.models.discovery_schedule import DiscoverySchedule
from app.models.observation import Observation
from app.models.user import User
from app.services import discovery_schedule_service, discovery_scheduler_executor


def _create_and_authorize_asset(client, headers, value, asset_type="domain"):
    resp = client.post("/assets", json={"asset_type": asset_type, "value": value}, headers=headers)
    assert resp.status_code == 201, resp.text
    asset = resp.json()
    confirm = client.post(
        f"/assets/{asset['id']}/confirm-authorization", json={"authorization_confirmed": True}, headers=headers
    )
    assert confirm.status_code == 200, confirm.text
    return asset


def _make_schedule(db, client, headers, email, value, provider_name="stub", interval_hours=6, asset_type="domain"):
    asset = _create_and_authorize_asset(client, headers, value, asset_type=asset_type)
    seed_asset = db.get(Asset, uuid.UUID(asset["id"]))
    user = db.query(User).filter(User.email == email).first()
    schedule = discovery_schedule_service.create_schedule(db, seed_asset, provider_name, interval_hours, user)
    return seed_asset, schedule


def test_successful_scheduled_execution_updates_schedule_state(client, register_user, db, executor_uses_test_db):
    headers = register_user(email="exec-success@example.com")
    seed_asset, schedule = _make_schedule(db, client, headers, "exec-success@example.com", "exec-success.example.com")

    runs = discovery_scheduler_executor.claim_due_schedules(db)
    assert len(runs) == 1
    run = runs[0]

    discovery_scheduler_executor.execute_scheduled_run(run.id, schedule.id)

    db.refresh(schedule)
    db.refresh(run)
    assert run.status == DiscoveryRunStatus.completed
    assert run.schedule_id == schedule.id
    assert schedule.claimed_at is None
    assert schedule.last_run_id == run.id
    assert schedule.last_run_at is not None
    assert schedule.enabled is True


def test_next_run_calculation(client, register_user, db, executor_uses_test_db):
    headers = register_user(email="exec-nextrun@example.com")
    seed_asset, schedule = _make_schedule(
        db, client, headers, "exec-nextrun@example.com", "exec-nextrun.example.com", interval_hours=8
    )
    before = datetime.now(timezone.utc)

    runs = discovery_scheduler_executor.claim_due_schedules(db)
    discovery_scheduler_executor.execute_scheduled_run(runs[0].id, schedule.id)

    db.refresh(schedule)
    expected = before + timedelta(hours=8)
    assert abs((schedule.next_run_at - expected).total_seconds()) < 30


def test_provider_exception_marks_run_failed_and_releases_schedule(
    client, register_user, db, executor_uses_test_db, monkeypatch
):
    headers = register_user(email="exec-exception@example.com")
    seed_asset, schedule = _make_schedule(db, client, headers, "exec-exception@example.com", "exec-exception.example.com")

    def _raise(self, seed_value):
        raise RuntimeError("simulated unexpected provider crash")

    monkeypatch.setattr(type(DISCOVERY_PROVIDER_REGISTRY["stub"]), "discover", _raise)

    runs = discovery_scheduler_executor.claim_due_schedules(db)
    discovery_scheduler_executor.execute_scheduled_run(runs[0].id, schedule.id)

    db.refresh(schedule)
    db.refresh(runs[0])
    assert runs[0].status == DiscoveryRunStatus.failed
    assert schedule.claimed_at is None  # released, not stuck


def test_authorization_revoked_before_execution_blocks_and_disables(client, register_user, db, executor_uses_test_db):
    headers = register_user(email="exec-revoked@example.com")
    seed_asset, schedule = _make_schedule(db, client, headers, "exec-revoked@example.com", "exec-revoked.example.com")

    runs = discovery_scheduler_executor.claim_due_schedules(db)

    seed_asset.authorization_confirmed = False
    db.commit()

    discovery_scheduler_executor.execute_scheduled_run(runs[0].id, schedule.id)

    db.refresh(schedule)
    db.refresh(runs[0])
    assert runs[0].status == DiscoveryRunStatus.failed
    assert "authoriz" in runs[0].error_message.lower() or "revoked" in runs[0].error_message.lower()
    assert schedule.enabled is False
    assert schedule.disabled_reason is not None
    assert schedule.claimed_at is None


def test_authorization_revoked_disabled_schedule_never_reclaimed(client, register_user, db, executor_uses_test_db):
    """A revoked authorization must prevent FUTURE scheduled execution,
    not just fail the one run in flight at revocation time."""
    headers = register_user(email="exec-revoked-future@example.com")
    seed_asset, schedule = _make_schedule(
        db, client, headers, "exec-revoked-future@example.com", "exec-revoked-future.example.com"
    )
    runs = discovery_scheduler_executor.claim_due_schedules(db)
    seed_asset.authorization_confirmed = False
    db.commit()
    discovery_scheduler_executor.execute_scheduled_run(runs[0].id, schedule.id)
    db.refresh(schedule)
    assert schedule.enabled is False

    # A later dispatch tick must never pick this schedule up again.
    later_runs = discovery_scheduler_executor.claim_due_schedules(db)
    assert schedule.id not in {r.schedule_id for r in later_runs}


def test_deactivated_asset_blocks_execution(client, register_user, db, executor_uses_test_db):
    headers = register_user(email="exec-deactivated@example.com")
    seed_asset, schedule = _make_schedule(db, client, headers, "exec-deactivated@example.com", "exec-deactivated.example.com")
    runs = discovery_scheduler_executor.claim_due_schedules(db)

    seed_asset.is_active = False
    db.commit()

    discovery_scheduler_executor.execute_scheduled_run(runs[0].id, schedule.id)
    db.refresh(schedule)
    db.refresh(runs[0])
    assert runs[0].status == DiscoveryRunStatus.failed
    assert schedule.enabled is False


def test_zero_result_run_still_completes_normally(client, register_user, db, executor_uses_test_db, monkeypatch):
    """A run finding nothing is a normal, successful outcome -- not a
    failure, and must not disable the schedule."""
    from app.discovery.base import DiscoveryProviderResult

    headers = register_user(email="exec-zero@example.com")
    seed_asset, schedule = _make_schedule(db, client, headers, "exec-zero@example.com", "exec-zero.example.com")

    def _empty(self, seed_value):
        return DiscoveryProviderResult(provider="stub", candidates=[])

    monkeypatch.setattr(type(DISCOVERY_PROVIDER_REGISTRY["stub"]), "discover", _empty)

    runs = discovery_scheduler_executor.claim_due_schedules(db)
    discovery_scheduler_executor.execute_scheduled_run(runs[0].id, schedule.id)

    db.refresh(schedule)
    db.refresh(runs[0])
    assert runs[0].status == DiscoveryRunStatus.completed
    assert schedule.enabled is True


def test_dependency_unmet_skips_run_without_disabling(client, register_user, db, executor_uses_test_db):
    """cloud depends_on network -- if network has never completed for
    this seed, a cloud schedule's run is skipped (cancelled), not
    failed, and the schedule stays enabled/claimable for the very next
    tick.
    """
    headers = register_user(email="exec-dependency@example.com")
    seed_asset, schedule = _make_schedule(
        db, client, headers, "exec-dependency@example.com", "93.184.216.201",
        provider_name="cloud", asset_type="ip_address",
    )

    runs = discovery_scheduler_executor.claim_due_schedules(db)
    discovery_scheduler_executor.execute_scheduled_run(runs[0].id, schedule.id)

    db.refresh(schedule)
    db.refresh(runs[0])
    assert runs[0].status == DiscoveryRunStatus.cancelled
    assert "network" in runs[0].error_message.lower()
    assert schedule.enabled is True
    assert schedule.claimed_at is None  # released for an immediate retry, not a full interval


def test_dependency_satisfied_allows_run(client, register_user, db, executor_uses_test_db):
    headers = register_user(email="exec-dependency-ok@example.com")
    seed_asset, schedule = _make_schedule(
        db, client, headers, "exec-dependency-ok@example.com", "93.184.216.202",
        provider_name="cloud", asset_type="ip_address",
    )
    user = db.query(User).filter(User.email == "exec-dependency-ok@example.com").first()

    # Simulate a prior successful "network" run for this exact seed.
    prior_run = DiscoveryRun(
        organization_id=seed_asset.organization_id,
        seed_asset_id=seed_asset.id,
        initiated_by=user.id,
        provider_name="network",
        status=DiscoveryRunStatus.completed,
    )
    db.add(prior_run)
    db.commit()

    runs = discovery_scheduler_executor.claim_due_schedules(db)
    discovery_scheduler_executor.execute_scheduled_run(runs[0].id, schedule.id)

    db.refresh(runs[0])
    assert runs[0].status != DiscoveryRunStatus.cancelled


def test_reap_stale_runs_marks_failed_not_completed(client, register_user, db, executor_uses_test_db):
    headers = register_user(email="exec-reap@example.com")
    seed_asset, schedule = _make_schedule(db, client, headers, "exec-reap@example.com", "exec-reap.example.com")
    runs = discovery_scheduler_executor.claim_due_schedules(db)
    run = runs[0]

    # Simulate a worker that claimed the run but was hard-killed before
    # finishing -- stuck in `running` well past the stale threshold.
    run.status = DiscoveryRunStatus.running
    run.started_at = datetime.now(timezone.utc) - discovery_scheduler_executor.STALE_CLAIM_TIMEOUT - timedelta(minutes=1)
    db.commit()

    reaped_count = discovery_scheduler_executor.reap_stale_runs(db)
    assert reaped_count == 1

    db.refresh(run)
    db.refresh(schedule)
    assert run.status == DiscoveryRunStatus.failed
    assert run.status != DiscoveryRunStatus.completed
    assert schedule.claimed_at is None


def test_reaped_run_does_not_trigger_disappearance_detection(client, register_user, db, executor_uses_test_db):
    """Step 9.9 safety semantics preserved: a reaped (never-completed)
    run must never cause a previously-discovered candidate to be marked
    disappeared -- disappearance detection only ever runs on
    discovery_service.execute_run's own successful-completion path,
    which a reaped run never reaches.
    """
    headers = register_user(email="exec-reap-disappear@example.com")
    seed_asset, schedule = _make_schedule(
        db, client, headers, "exec-reap-disappear@example.com", "exec-reap-disappear.example.com",
        provider_name="stub",
    )

    # First, a genuinely successful run establishes a real candidate.
    runs = discovery_scheduler_executor.claim_due_schedules(db)
    discovery_scheduler_executor.execute_scheduled_run(runs[0].id, schedule.id)
    db.refresh(schedule)

    all_relationships_before = (
        db.query(AssetRelationship)
        .filter(AssetRelationship.status != LifecycleStatus.disappeared)
        .all()
    )
    assert len(all_relationships_before) >= 1

    # Second attempt gets stuck and reaped instead of completing.
    schedule.next_run_at = datetime.now(timezone.utc)
    db.commit()
    runs2 = discovery_scheduler_executor.claim_due_schedules(db)
    run2 = runs2[0]
    run2.status = DiscoveryRunStatus.running
    run2.started_at = datetime.now(timezone.utc) - discovery_scheduler_executor.STALE_CLAIM_TIMEOUT - timedelta(minutes=1)
    db.commit()

    discovery_scheduler_executor.reap_stale_runs(db)

    all_relationships_after = (
        db.query(AssetRelationship)
        .filter(AssetRelationship.status != LifecycleStatus.disappeared)
        .all()
    )
    assert len(all_relationships_after) == len(all_relationships_before)  # nothing marked disappeared


def test_run_twice_dispatch_guard_prevents_duplicate_execution(client, register_user, db, executor_uses_test_db):
    """A redelivered/duplicate dispatch message for the exact same
    run_id must not execute the provider twice."""
    headers = register_user(email="exec-duplicate@example.com")
    seed_asset, schedule = _make_schedule(db, client, headers, "exec-duplicate@example.com", "exec-duplicate.example.com")
    runs = discovery_scheduler_executor.claim_due_schedules(db)
    run = runs[0]

    discovery_scheduler_executor.execute_scheduled_run(run.id, schedule.id)
    db.refresh(run)
    completed_at_first = run.completed_at

    # Re-invoke with the exact same (already-completed) run_id.
    discovery_scheduler_executor.execute_scheduled_run(run.id, schedule.id)
    db.refresh(run)
    assert run.completed_at == completed_at_first  # untouched -- the atomic status guard backed off
