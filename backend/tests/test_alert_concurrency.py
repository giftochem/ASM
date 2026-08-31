"""Step 9.12.16: genuine PostgreSQL concurrency for alert creation --
real threads, each with its own TestSessionLocal() session, racing to
create an alert with the IDENTICAL fingerprint, mirroring
test_discovery_scheduler_concurrency.py's established pattern. This
proves uq_alerts_org_fingerprint_open (a partial unique index, see
app/models/alert.py) genuinely serializes concurrent alert creation
through real Postgres locking -- not through any assumption about
single-threaded test execution, and not through a Python lock.
"""

import threading
import uuid

from app.core.enums import AlertPriority, AlertType
from app.models.alert import Alert
from app.models.asset import Asset
from tests.conftest import TestSessionLocal


def _seed_asset(client, headers, value):
    resp = client.post("/assets", json={"asset_type": "domain", "value": value}, headers=headers)
    assert resp.status_code == 201, resp.text
    return resp.json()


def test_two_concurrent_alert_creations_for_the_same_fingerprint_never_both_insert(client, register_user, db):
    headers = register_user(email="conc-alert@example.com")
    asset = _seed_asset(client, headers, "conc-alert.example.com")
    asset_id = uuid.UUID(asset["id"])
    seed_asset = db.get(Asset, asset_id)
    organization_id = seed_asset.organization_id

    barrier = threading.Barrier(2)
    results: dict[str, bool] = {}

    def _create(name: str) -> None:
        from app.services import alert_service

        session = TestSessionLocal()
        try:
            local_asset = session.get(Asset, asset_id)
            candidate = alert_service.AlertCandidate(
                alert_type=AlertType.certificate_changed,
                asset_id=local_asset.id,
                relationship_id=None,
                source_observation_id=None,
                discovery_run_id=None,
                priority=AlertPriority.medium,
                title="Concurrent alert",
                description="d",
                evidence={"race": name},
                fingerprint=alert_service._fingerprint(
                    local_asset.organization_id, AlertType.certificate_changed, local_asset.id, "race-slot"
                ),
            )
            barrier.wait(timeout=5)
            alert, created = alert_service._create_or_update_alert(session, local_asset.organization_id, None, candidate)
            session.commit()
            results[name] = created
        finally:
            session.close()

    t1 = threading.Thread(target=_create, args=("t1",))
    t2 = threading.Thread(target=_create, args=("t2",))
    t1.start()
    t2.start()
    t1.join(timeout=10)
    t2.join(timeout=10)

    assert "t1" in results and "t2" in results
    creators = [name for name, created in results.items() if created]
    updaters = [name for name, created in results.items() if not created]
    assert len(creators) == 1  # exactly one thread's INSERT won
    assert len(updaters) == 1  # the other backed off into an UPDATE via the caught IntegrityError

    db.expire_all()
    matching = db.query(Alert).filter(Alert.organization_id == organization_id, Alert.asset_id == asset_id).all()
    assert len(matching) == 1  # exactly one row -- never two, never zero
    assert matching[0].occurrence_count == 2  # both racing evaluations were accounted for


def test_three_concurrent_creations_for_the_same_fingerprint_produce_exactly_one_row(client, register_user, db):
    """A wider race (3 workers) to more strongly rule out a coincidental
    pass under only 2 threads."""
    headers = register_user(email="conc-alert-wide@example.com")
    asset = _seed_asset(client, headers, "conc-alert-wide.example.com")
    asset_id = uuid.UUID(asset["id"])

    barrier = threading.Barrier(3)
    results: dict[str, bool] = {}

    def _create(name: str) -> None:
        from app.services import alert_service

        session = TestSessionLocal()
        try:
            local_asset = session.get(Asset, asset_id)
            candidate = alert_service.AlertCandidate(
                alert_type=AlertType.certificate_changed,
                asset_id=local_asset.id,
                relationship_id=None,
                source_observation_id=None,
                discovery_run_id=None,
                priority=AlertPriority.medium,
                title="Concurrent alert",
                description="d",
                evidence={},
                fingerprint=alert_service._fingerprint(
                    local_asset.organization_id, AlertType.certificate_changed, local_asset.id, "wide-slot"
                ),
            )
            barrier.wait(timeout=5)
            _, created = alert_service._create_or_update_alert(session, local_asset.organization_id, None, candidate)
            session.commit()
            results[name] = created
        finally:
            session.close()

    threads = [threading.Thread(target=_create, args=(f"t{i}",)) for i in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)

    assert len(results) == 3
    assert sum(1 for created in results.values() if created) == 1

    db.expire_all()
    matching = db.query(Alert).filter(Alert.asset_id == asset_id).all()
    assert len(matching) == 1
    assert matching[0].occurrence_count == 3
