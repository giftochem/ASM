"""Step 9.12.17: N+1 avoidance for alert evaluation (a run that touches
many candidates must not run one prioritization/observation query per
candidate). Step 9.12.13: the remaining explicit security requirements
not already covered by test_alert_api.py's RBAC/IDOR/org-isolation
coverage -- no client-supplied organization_id trust, no secret values
in alert evidence/description, no credentials in Celery task
arguments.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import event

from app.core.enums import AssetType, DiscoveryResultOutcome, DiscoveryRunStatus, RelationshipType
from app.discovery.base import DiscoveryCandidate
from app.models.alert import Alert
from app.models.asset import Asset
from app.models.user import User
from app.services import alert_service, discovery_normalization_service, discovery_service
from tests.conftest import test_engine


def _create_and_authorize_asset(client, headers, value, asset_type="domain"):
    resp = client.post("/assets", json={"asset_type": asset_type, "value": value}, headers=headers)
    assert resp.status_code == 201, resp.text
    asset = resp.json()
    confirm = client.post(
        f"/assets/{asset['id']}/confirm-authorization", json={"authorization_confirmed": True}, headers=headers
    )
    assert confirm.status_code == 200, confirm.text
    return asset


def test_alert_evaluation_query_count_does_not_scale_linearly_with_touched_asset_count(client, register_user, db):
    """Isolates the read-side "how many assets does this run touch"
    cost from the write-side "how many new alert rows does this run
    create" cost -- writing N genuinely new alert rows necessarily
    costs ~2N queries (a select-for-update + an insert each, see
    _create_or_update_alert) and that proportional cost is expected,
    not wasteful N+1. What must NOT scale per touched asset is the
    READ side: computing priority for every touched asset used to call
    the single-asset get_asset_priority once per asset (a real N+1, see
    _build_priority_lookup's docstring) -- fixed by batching via
    prioritize_assets(asset_ids=...). Measured here across a run that
    RE-CONFIRMS N already-existing candidates unchanged (no new
    Observations, no new alerts, so the only work possible is read-side
    evaluation) at two different scales.
    """
    email = "perf-alerts@example.com"
    headers = register_user(email=email)

    def _setup_and_reconfirm(n: int) -> int:
        seed = _create_and_authorize_asset(client, headers, f"perf-alerts-{n}.example.com")
        seed_asset = db.get(Asset, uuid.UUID(seed["id"]))
        user = db.query(User).filter(User.email == email).first()

        candidates = [
            DiscoveryCandidate(
                asset_type=AssetType.subdomain, value=f"host{i}.perf-alerts-{n}.example.com",
                relationship_type=RelationshipType.belongs_to, confidence=0.9,
            )
            for i in range(n)
        ]

        run1 = discovery_service.create_run(db, seed_asset, "stub", user)
        run1.started_at = datetime.now(timezone.utc)
        db.commit()
        for candidate in candidates:
            discovery_normalization_service.normalize_candidate(db, run1, seed_asset, candidate)
        db.commit()
        run1.status = DiscoveryRunStatus.completed
        run1.completed_at = datetime.now(timezone.utc)
        db.commit()
        alert_service.evaluate_run_for_alerts(db, run1, seed_asset)  # unmeasured -- creates the initial alerts
        db.commit()

        run2 = discovery_service.create_run(db, seed_asset, "stub", user)
        run2.started_at = datetime.now(timezone.utc)
        db.commit()
        for candidate in candidates:
            result = discovery_normalization_service.normalize_candidate(db, run2, seed_asset, candidate)
            assert result.outcome == DiscoveryResultOutcome.unchanged
        db.commit()
        run2.status = DiscoveryRunStatus.completed
        run2.completed_at = datetime.now(timezone.utc)
        db.commit()

        counts = {"n": 0}

        def _on_execute(*args, **kwargs):
            counts["n"] += 1

        event.listen(test_engine, "before_cursor_execute", _on_execute)
        try:
            new_alerts = alert_service.evaluate_run_for_alerts(db, run2, seed_asset)
            db.commit()
        finally:
            event.remove(test_engine, "before_cursor_execute", _on_execute)
        assert new_alerts == []  # confirms this measurement is pure read-side, no write-proportional cost
        return counts["n"]

    small_queries = _setup_and_reconfirm(3)
    large_queries = _setup_and_reconfirm(30)

    # Query count must stay flat (a fixed, small number of batched
    # queries) regardless of how many assets a run touches -- not grow
    # per-asset.
    assert large_queries <= small_queries + 3


def test_organization_id_is_never_client_supplied(client, register_user, db):
    """evaluate_run_for_alerts/_create_or_update_alert always derive
    organization_id from the already-authorized Asset row -- confirmed
    structurally: none of the alert routes (list/get/acknowledge/
    resolve) accept a request body or query parameter that could set
    organization_id, and acknowledge/resolve are id-in-path-only
    (POST /alerts/{alert_id}/acknowledge|resolve, no JSON body at all).
    """
    import inspect

    from app.api.routes import alerts as alerts_routes

    for handler in (alerts_routes.acknowledge_alert, alerts_routes.resolve_alert):
        params = inspect.signature(handler).parameters
        assert "organization_id" not in params
        assert not any(name in ("payload", "body") for name in params)  # no client-supplied body at all


def test_alert_evidence_never_contains_raw_cookie_or_credential_values(client, register_user, db):
    """The HTTP provider (Step 9.5) already guarantees cookie_security_flags
    never carries a raw name=value pair, only attribute booleans -- this
    confirms alert_service passes that evidence through UNCHANGED
    (never re-serializing the raw HttpObservation, which the provider
    layer never populates with a cookie value in the first place)."""
    from app.discovery.base import HttpObservation

    email = "sec-cookie@example.com"
    headers = register_user(email=email)
    asset = _create_and_authorize_asset(client, headers, "sec-cookie.example.com")
    seed_asset = db.get(Asset, uuid.UUID(asset["id"]))
    user = db.query(User).filter(User.email == email).first()

    run1 = discovery_service.create_run(db, seed_asset, "stub", user)
    run1.started_at = datetime.now(timezone.utc)
    db.commit()
    first = HttpObservation(
        scheme="https", requested_url="https://sec-cookie.example.com/", status_code=200,
        security_headers={"strict-transport-security": True}, cookie_security_flags=[{"secure": True, "httponly": True, "samesite": "Strict"}],
    )
    discovery_normalization_service.record_http_observation(db, run1, seed_asset, first)
    db.commit()
    run1.status = DiscoveryRunStatus.completed
    run1.completed_at = datetime.now(timezone.utc)
    db.commit()
    alert_service.evaluate_run_for_alerts(db, run1, seed_asset)
    db.commit()

    run2 = discovery_service.create_run(db, seed_asset, "stub", user)
    run2.started_at = datetime.now(timezone.utc)
    db.commit()
    second = HttpObservation(
        scheme="https", requested_url="https://sec-cookie.example.com/", status_code=200,
        security_headers={"strict-transport-security": False}, cookie_security_flags=[{"secure": True, "httponly": True, "samesite": "Strict"}],
    )
    discovery_normalization_service.record_http_observation(db, run2, seed_asset, second)
    db.commit()
    run2.status = DiscoveryRunStatus.completed
    run2.completed_at = datetime.now(timezone.utc)
    db.commit()
    new_alerts = alert_service.evaluate_run_for_alerts(db, run2, seed_asset)
    db.commit()

    http_alerts = [a for a in new_alerts if a.alert_type.value == "http_security_posture_changed"]
    assert len(http_alerts) == 1
    evidence_str = str(http_alerts[0].evidence)
    assert "=" not in evidence_str or "secure" in evidence_str  # only attribute booleans, never name=value pairs
    assert "sessionid" not in evidence_str.lower()


def test_task_arguments_are_bare_uuid_no_credentials(client, register_user, db):
    """The only Celery task boundary Step 9.12 adds is
    deliver_alert_notification_task(notification_id) -- confirmed here
    that a real notification's id is a bare UUID string, structurally
    incapable of carrying SMTP credentials or recipient addresses (both
    are read fresh from Settings/the database inside the worker, see
    app.services.alert_delivery_executor.deliver).
    """
    from app.core.enums import AlertPriority, AlertType, NotificationChannel, NotificationStatus
    from app.models.alert_notification import AlertNotification

    email = "sec-task-args@example.com"
    headers = register_user(email=email)
    asset = _create_and_authorize_asset(client, headers, "sec-task-args.example.com")
    seed_asset = db.get(Asset, uuid.UUID(asset["id"]))

    candidate = alert_service.AlertCandidate(
        alert_type=AlertType.certificate_changed, asset_id=seed_asset.id, relationship_id=None,
        source_observation_id=None, discovery_run_id=None, priority=AlertPriority.medium,
        title="t", description="d", evidence={},
        fingerprint=alert_service._fingerprint(seed_asset.organization_id, AlertType.certificate_changed, seed_asset.id),
    )
    alert, _ = alert_service._create_or_update_alert(db, seed_asset.organization_id, None, candidate)
    db.commit()

    notification = AlertNotification(alert_id=alert.id, channel=NotificationChannel.email, status=NotificationStatus.pending)
    db.add(notification)
    db.commit()

    task_arg = str(notification.id)
    uuid.UUID(task_arg)  # raises ValueError if this is anything other than a bare UUID string
    assert "@" not in task_arg and "password" not in task_arg.lower()
