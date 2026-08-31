"""Race-safety regression coverage for scan cancellation vs. execution.

scan_service.cancel_scan and scan_executor.execute_scan's queued->running
transition both use an atomic conditional UPDATE (`... WHERE status =
'queued'`) rather than "read status in Python, then write" — the latter
would let a worker that already passed its authorization re-check
unconditionally overwrite a cancellation that committed a moment later.
These tests drive the two code paths from separate threads with separate
DB sessions (mirroring how a real API request and a real worker process
would actually race) and assert the outcome is always self-consistent:
exactly one of {cancelled, running/completed} wins, never both, and the
loser's write is cleanly rejected (rowcount 0) rather than silently lost
or duplicated.
"""

import threading

from app.core.enums import ScanStatus
from app.models.asset import Asset
from app.models.finding import Finding
from app.models.user import User
from app.services import scan_executor, scan_service
from tests.conftest import TestSessionLocal


def _confirmed_asset_and_queued_scan(client, headers, db, value="example.com"):
    asset_payload = client.post(
        "/assets", json={"asset_type": "domain", "value": value}, headers=headers
    ).json()
    client.post(
        f"/assets/{asset_payload['id']}/confirm-authorization",
        json={"authorization_confirmed": True},
        headers=headers,
    )
    user = db.query(User).filter(User.email == "admin@example.com").first()
    asset = db.query(Asset).filter(Asset.id == asset_payload["id"]).first()
    modules = scan_service.validate_scan_request(asset, ["whois"])
    scan = scan_service.create_scan(db, asset, modules, user)
    return asset, scan


def test_concurrent_cancel_and_execute_never_both_succeed(client, register_user, db, executor_uses_test_db):
    headers = register_user()
    _, scan = _confirmed_asset_and_queued_scan(client, headers, db)
    scan_id = scan.id

    barrier = threading.Barrier(2)
    results = {}

    def _do_cancel():
        session = TestSessionLocal()
        try:
            barrier.wait(timeout=5)
            local_scan = session.get(type(scan), scan_id)
            try:
                scan_service.cancel_scan(session, local_scan)
                results["cancel"] = "succeeded"
            except ValueError:
                results["cancel"] = "lost_race"
        finally:
            session.close()

    def _do_execute():
        barrier.wait(timeout=5)
        scan_executor.execute_scan(scan_id)
        results["execute"] = "ran"

    t1 = threading.Thread(target=_do_cancel)
    t2 = threading.Thread(target=_do_execute)
    t1.start()
    t2.start()
    t1.join(timeout=10)
    t2.join(timeout=10)

    assert "cancel" in results and "execute" in results

    db.expire_all()
    final_scan = db.get(type(scan), scan_id)

    if results["cancel"] == "succeeded":
        # Cancellation won: execute_scan must have seen the cancelled
        # status (either before or after its own transition attempt) and
        # refused to run any module -- no findings, status stays cancelled.
        assert final_scan.status == ScanStatus.cancelled
        findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
        assert findings == []
    else:
        # Execution won the race to 'running' first: the cancellation
        # attempt must have cleanly lost (ValueError, not a silent
        # no-op or a corrupted status), and the scan proceeded normally.
        assert results["cancel"] == "lost_race"
        assert final_scan.status in (ScanStatus.completed, ScanStatus.failed)


def test_atomic_update_rowcount_reflects_true_winner(client, register_user, db, executor_uses_test_db):
    """More directly: manually pre-empt the transition (simulating a
    cancellation that already committed) and confirm scan_executor's own
    atomic UPDATE reports zero rows affected rather than proceeding.
    """
    headers = register_user()
    _, scan = _confirmed_asset_and_queued_scan(client, headers, db)

    cancelled = scan_service.cancel_scan(db, scan)
    assert cancelled.status == ScanStatus.cancelled

    # Now let the "worker" try anyway -- must find nothing to do and must
    # not flip the already-cancelled scan to failed/running.
    scan_executor.execute_scan(scan.id)

    db.refresh(scan)
    assert scan.status == ScanStatus.cancelled
    findings = db.query(Finding).filter(Finding.scan_id == scan.id).all()
    assert findings == []
