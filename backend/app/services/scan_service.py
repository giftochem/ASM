"""Synchronous, request-facing half of the scan pipeline: everything that
can be decided before any network call — is this even allowed, what
modules apply, create the Scan row — stays here and runs inline in the
API route so the client gets an immediate 403/400 for deterministic
errors exactly like Phase 1 did.

The actual module execution (network calls, persistence, the mandatory
re-check of authorization immediately before running) lives in
app.services.scan_executor, invoked asynchronously via
app.tasks.scan_tasks — see that module for why the check is repeated
rather than trusted from here.
"""

from datetime import datetime, timezone

from sqlalchemy import update
from sqlalchemy.orm import Session

from app.core.enums import ScanStatus
from app.core.exceptions import AuthorizationNotConfirmedError
from app.models.asset import Asset
from app.models.scan import Scan
from app.models.user import User
from app.scanners.registry import MODULE_REGISTRY, get_module


def validate_scan_request(asset: Asset, requested_modules: list[str] | None) -> list[str]:
    """The authorization guardrail's first enforcement point. Raises
    AuthorizationNotConfirmedError / ValueError for the API route to
    translate into 403 / 400 — same contract as Phase 1.
    """
    if not asset.authorization_confirmed:
        raise AuthorizationNotConfirmedError(
            f"Asset '{asset.value}' does not have authorization_confirmed=true. "
            "Confirm authorization via POST /assets/{id}/confirm-authorization before scanning."
        )

    if requested_modules is None:
        # Active-scanning modules (port_scanner) never run just because a
        # caller omitted `modules` — they must be named explicitly.
        modules = [
            name
            for name, mod in MODULE_REGISTRY.items()
            if mod.supports(asset.asset_type) and not mod.requires_explicit_opt_in
        ]
        if not modules:
            raise ValueError(f"no scanner modules support asset_type '{asset.asset_type.value}'")
        return modules

    for name in requested_modules:
        module = get_module(name)
        if module is None:
            raise ValueError(f"unknown scanner module: '{name}'")
        if not module.supports(asset.asset_type):
            raise ValueError(
                f"module '{name}' does not support asset_type '{asset.asset_type.value}'"
            )
    return requested_modules


def create_scan(db: Session, asset: Asset, modules: list[str], user: User) -> Scan:
    scan = Scan(
        asset_id=asset.id,
        initiated_by=user.id,
        status=ScanStatus.queued,
        modules_requested=modules,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


def queue_scan(scan: Scan) -> None:
    """Enqueues execution. Imports the task lazily to avoid a hard import
    cycle between services and tasks at module load time.
    """
    from app.tasks.scan_tasks import execute_scan_task

    execute_scan_task.delay(str(scan.id))


def cancel_scan(db: Session, scan: Scan) -> Scan:
    """Only valid while still queued — once execution has started, the
    worker owns the scan's lifecycle.

    Uses an atomic conditional UPDATE (... WHERE status = 'queued') rather
    than "read status in Python, then write" — the latter is a real race:
    a worker could read status='queued' in scan_executor, pass its own
    check, and then unconditionally write status='running' a moment after
    this function's read but before its write, silently clobbering a
    cancellation that had already committed. The WHERE clause makes
    Postgres itself the arbiter of which of the two concurrent
    transitions (this cancellation, or the worker's queued->running) wins
    — whichever commits first; the loser's UPDATE simply matches zero
    rows and is detected via rowcount, not overwritten data.
    """
    now = datetime.now(timezone.utc)
    result = db.execute(
        update(Scan)
        .where(Scan.id == scan.id, Scan.status == ScanStatus.queued)
        .values(status=ScanStatus.cancelled, completed_at=now)
    )
    db.commit()

    if result.rowcount == 0:
        db.refresh(scan)
        raise ValueError(f"cannot cancel a scan in status '{scan.status.value}'")

    db.refresh(scan)
    return scan
