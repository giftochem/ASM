"""Regression coverage for the fail-closed re-authorization check in
scan_executor: a scan queued while authorization was true must not
execute if authorization is revoked before a worker gets to it.

Deliberately does not use Celery/eager mode — it calls
scan_service.create_scan()/queue_scan()-equivalent steps and
scan_executor.execute_scan() directly, so the "time passes between queue
and execution" window is fully under the test's control rather than
racing real async execution.
"""

from app.core.enums import ScanStatus
from app.models.asset import Asset
from app.models.finding import Finding
from app.models.user import User
from app.services import scan_executor, scan_service


def _create_and_confirm_asset(client, headers, value="example.com"):
    asset = client.post(
        "/assets", json={"asset_type": "domain", "value": value}, headers=headers
    ).json()
    client.post(
        f"/assets/{asset['id']}/confirm-authorization",
        json={"authorization_confirmed": True},
        headers=headers,
    )
    return asset


def test_revoking_authorization_after_queueing_blocks_execution(
    client, register_user, db, executor_uses_test_db
):
    headers = register_user()
    asset_payload = _create_and_confirm_asset(client, headers)

    user = db.query(User).filter(User.email == "admin@example.com").first()
    asset = db.query(Asset).filter(Asset.id == asset_payload["id"]).first()
    assert asset.authorization_confirmed is True

    modules = scan_service.validate_scan_request(asset, ["whois"])
    scan = scan_service.create_scan(db, asset, modules, user)
    assert scan.status == ScanStatus.queued

    # Revoke authorization through the real API — simulating an
    # admin/analyst changing their mind between queueing and execution.
    revoke_resp = client.post(f"/assets/{asset.id}/revoke-authorization", json={}, headers=headers)
    assert revoke_resp.status_code == 200
    assert revoke_resp.json()["authorization_confirmed"] is False

    # Now simulate the worker picking up the (already queued) scan.
    scan_executor.execute_scan(scan.id)

    db.refresh(scan)
    assert scan.status == ScanStatus.failed
    assert scan.error_message is not None
    assert "revoked" in scan.error_message.lower()

    persisted_findings = db.query(Finding).filter(Finding.scan_id == scan.id).all()
    assert persisted_findings == []


def test_deactivating_asset_after_queueing_blocks_execution(client, register_user, db, executor_uses_test_db):
    headers = register_user()
    asset_payload = _create_and_confirm_asset(client, headers)

    user = db.query(User).filter(User.email == "admin@example.com").first()
    asset = db.query(Asset).filter(Asset.id == asset_payload["id"]).first()

    modules = scan_service.validate_scan_request(asset, ["whois"])
    scan = scan_service.create_scan(db, asset, modules, user)

    asset.is_active = False
    db.commit()

    scan_executor.execute_scan(scan.id)

    db.refresh(scan)
    assert scan.status == ScanStatus.failed
    assert "deactivated" in scan.error_message.lower()


def test_cancelling_queued_scan_blocks_execution(client, register_user, db, executor_uses_test_db):
    headers = register_user()
    asset_payload = _create_and_confirm_asset(client, headers)

    user = db.query(User).filter(User.email == "admin@example.com").first()
    asset = db.query(Asset).filter(Asset.id == asset_payload["id"]).first()

    modules = scan_service.validate_scan_request(asset, ["whois"])
    scan = scan_service.create_scan(db, asset, modules, user)

    cancel_resp = client.post(f"/scans/{scan.id}/cancel", headers=headers)
    assert cancel_resp.status_code == 200
    assert cancel_resp.json()["status"] == "cancelled"

    scan_executor.execute_scan(scan.id)

    db.refresh(scan)
    # Still cancelled, not overwritten back to failed/completed by a
    # worker that shouldn't have touched it at all.
    assert scan.status == ScanStatus.cancelled


def test_scan_still_executes_when_nothing_changed(client, register_user, db, executor_uses_test_db, monkeypatch):
    """Sanity check: the fail-closed checks don't block a legitimate,
    still-authorized scan.
    """
    from app.scanners.base import ScanModuleResult
    from app.scanners.whois_module import WhoisModule

    # What's under test is the authorization gate, not WHOIS -- the real
    # module would query live WHOIS servers (whois.iana.org and onward).
    executed_targets: list[str] = []

    def _no_network(self, target):
        executed_targets.append(target)
        return ScanModuleResult(module="whois")

    monkeypatch.setattr(WhoisModule, "run", _no_network)

    headers = register_user()
    asset_payload = _create_and_confirm_asset(client, headers)

    user = db.query(User).filter(User.email == "admin@example.com").first()
    asset = db.query(Asset).filter(Asset.id == asset_payload["id"]).first()

    modules = scan_service.validate_scan_request(asset, ["whois"])
    scan = scan_service.create_scan(db, asset, modules, user)

    scan_executor.execute_scan(scan.id)

    db.refresh(scan)
    assert scan.status == ScanStatus.completed
    assert executed_targets == ["example.com"]  # the module really was run, not skipped by the gate
