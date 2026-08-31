"""Step 9.12.6: alert lifecycle (open -> acknowledged -> resolved),
plus the non-reopenable-but-recurrable semantics already exercised more
deeply in test_alert_deduplication.py's resolved-alert test.
"""

import uuid
from datetime import datetime, timezone

import pytest

from app.core.enums import AlertPriority, AlertStatus, AlertType, DiscoveryRunStatus
from app.models.alert import Alert
from app.models.asset import Asset
from app.models.user import User
from app.services import alert_service


def _make_open_alert(db, seed_asset, user, *, suffix="a") -> Alert:
    now = datetime.now(timezone.utc)
    candidate = alert_service.AlertCandidate(
        alert_type=AlertType.certificate_changed,
        asset_id=seed_asset.id,
        relationship_id=None,
        source_observation_id=None,
        discovery_run_id=None,
        priority=AlertPriority.medium,
        title=f"Test alert {suffix}",
        description="A test alert",
        evidence={"suffix": suffix},
        fingerprint=alert_service._fingerprint(seed_asset.organization_id, AlertType.certificate_changed, seed_asset.id, suffix),
    )
    alert, _ = alert_service._create_or_update_alert(db, seed_asset.organization_id, None, candidate)
    db.commit()
    db.refresh(alert)
    return alert


def _seed(client, register_user, db, email):
    headers = register_user(email=email)
    resp = client.post("/assets", json={"asset_type": "domain", "value": f"{email.split('@')[0]}.example.com"}, headers=headers)
    assert resp.status_code == 201, resp.text
    asset = resp.json()
    confirm = client.post(
        f"/assets/{asset['id']}/confirm-authorization", json={"authorization_confirmed": True}, headers=headers
    )
    assert confirm.status_code == 200, confirm.text
    seed_asset = db.get(Asset, uuid.UUID(asset["id"]))
    user = db.query(User).filter(User.email == email).first()
    return headers, seed_asset, user


def test_open_alert_can_be_acknowledged(client, register_user, db):
    _, seed_asset, user = _seed(client, register_user, db, "life-ack@example.com")
    alert = _make_open_alert(db, seed_asset, user)

    result = alert_service.acknowledge_alert(db, alert, user.id)
    assert result.status == AlertStatus.acknowledged
    assert result.acknowledged_at is not None
    assert result.acknowledged_by == user.id


def test_acknowledged_alert_cannot_be_acknowledged_again(client, register_user, db):
    _, seed_asset, user = _seed(client, register_user, db, "life-ack-twice@example.com")
    alert = _make_open_alert(db, seed_asset, user)
    alert_service.acknowledge_alert(db, alert, user.id)

    with pytest.raises(ValueError, match="not open"):
        alert_service.acknowledge_alert(db, alert, user.id)


def test_open_alert_can_be_resolved_directly(client, register_user, db):
    """Skipping acknowledgement entirely is a valid, common workflow."""
    _, seed_asset, user = _seed(client, register_user, db, "life-resolve-direct@example.com")
    alert = _make_open_alert(db, seed_asset, user)

    result = alert_service.resolve_alert(db, alert, user.id)
    assert result.status == AlertStatus.resolved
    assert result.resolved_at is not None
    assert result.resolved_by == user.id


def test_acknowledged_alert_can_be_resolved(client, register_user, db):
    _, seed_asset, user = _seed(client, register_user, db, "life-ack-then-resolve@example.com")
    alert = _make_open_alert(db, seed_asset, user)
    alert_service.acknowledge_alert(db, alert, user.id)

    result = alert_service.resolve_alert(db, alert, user.id)
    assert result.status == AlertStatus.resolved


def test_resolved_alert_cannot_be_resolved_again(client, register_user, db):
    _, seed_asset, user = _seed(client, register_user, db, "life-resolve-twice@example.com")
    alert = _make_open_alert(db, seed_asset, user)
    alert_service.resolve_alert(db, alert, user.id)

    with pytest.raises(ValueError, match="already resolved"):
        alert_service.resolve_alert(db, alert, user.id)


def test_priority_only_ever_increases_on_dedup_update_never_decreases(client, register_user, db):
    _, seed_asset, user = _seed(client, register_user, db, "life-priority@example.com")
    fingerprint = alert_service._fingerprint(seed_asset.organization_id, AlertType.certificate_changed, seed_asset.id, "slot")

    high_candidate = alert_service.AlertCandidate(
        alert_type=AlertType.certificate_changed, asset_id=seed_asset.id, relationship_id=None,
        source_observation_id=None, discovery_run_id=None, priority=AlertPriority.high,
        title="t", description="d", evidence={}, fingerprint=fingerprint,
    )
    alert, created = alert_service._create_or_update_alert(db, seed_asset.organization_id, None, high_candidate)
    db.commit()
    assert created and alert.priority == AlertPriority.high

    low_candidate = alert_service.AlertCandidate(
        alert_type=AlertType.certificate_changed, asset_id=seed_asset.id, relationship_id=None,
        source_observation_id=None, discovery_run_id=None, priority=AlertPriority.low,
        title="t", description="d2", evidence={}, fingerprint=fingerprint,
    )
    alert2, created2 = alert_service._create_or_update_alert(db, seed_asset.organization_id, None, low_candidate)
    db.commit()
    assert not created2
    assert alert2.id == alert.id
    assert alert2.priority == AlertPriority.high  # never downgraded
    assert alert2.occurrence_count == 2

    critical_candidate = alert_service.AlertCandidate(
        alert_type=AlertType.certificate_changed, asset_id=seed_asset.id, relationship_id=None,
        source_observation_id=None, discovery_run_id=None, priority=AlertPriority.critical,
        title="t", description="d3", evidence={}, fingerprint=fingerprint,
    )
    alert3, created3 = alert_service._create_or_update_alert(db, seed_asset.organization_id, None, critical_candidate)
    db.commit()
    assert not created3
    assert alert3.priority == AlertPriority.critical  # upgraded
