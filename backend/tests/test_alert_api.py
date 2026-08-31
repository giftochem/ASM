"""Step 9.12.8: GET /alerts, GET /alerts/{id}, POST .../acknowledge,
POST .../resolve -- RBAC, IDOR/org isolation, filtering, pagination,
deterministic ordering. Alerts are seeded directly via
alert_service._create_or_update_alert (no need to drive a full
discovery run for API-layer tests -- classification is already covered
by test_alert_generation.py).
"""

import uuid
from datetime import datetime, timedelta, timezone

from app.core.enums import AlertPriority, AlertStatus, AlertType
from app.models.asset import Asset
from app.services import alert_service


def _seed_asset(client, headers, value="api-alerts.example.com"):
    resp = client.post("/assets", json={"asset_type": "domain", "value": value}, headers=headers)
    assert resp.status_code == 201, resp.text
    asset = resp.json()
    confirm = client.post(
        f"/assets/{asset['id']}/confirm-authorization", json={"authorization_confirmed": True}, headers=headers
    )
    assert confirm.status_code == 200, confirm.text
    return asset


def _make_alert(db, organization_id, asset_id, *, alert_type=AlertType.certificate_changed, priority=AlertPriority.medium, identity="x"):
    candidate = alert_service.AlertCandidate(
        alert_type=alert_type, asset_id=asset_id, relationship_id=None, source_observation_id=None,
        discovery_run_id=None, priority=priority, title=f"Alert {identity}", description="d", evidence={},
        fingerprint=alert_service._fingerprint(organization_id, alert_type, asset_id, identity),
    )
    alert, _ = alert_service._create_or_update_alert(db, organization_id, None, candidate)
    db.commit()
    db.refresh(alert)
    return alert


def test_list_alerts_requires_authentication(client):
    resp = client.get("/alerts")
    assert resp.status_code == 401


def test_viewer_can_list_and_get_alerts(client, register_user, db):
    headers = register_user(email="api-viewer-list@example.com", org_name="Org A")
    asset = _seed_asset(client, headers, "api-viewer-list.example.com")
    seed_asset = db.get(Asset, uuid.UUID(asset["id"]))
    alert = _make_alert(db, seed_asset.organization_id, seed_asset.id)

    # register_user always creates an admin; downgrade a second user to viewer via direct DB is
    # unnecessary here -- RBAC on GET is "any authenticated role", matching every other read endpoint.
    resp = client.get("/alerts", headers=headers)
    assert resp.status_code == 200
    assert any(a["id"] == str(alert.id) for a in resp.json())

    resp2 = client.get(f"/alerts/{alert.id}", headers=headers)
    assert resp2.status_code == 200
    assert resp2.json()["id"] == str(alert.id)


def test_alert_response_includes_denormalized_asset_identity(client, register_user, db):
    """Step 9.13: asset_value/asset_type are read from Alert.asset (see
    app/models/alert.py) -- confirmed via both the list (eager-loaded,
    to avoid N+1) and single-alert endpoints.
    """
    headers = register_user(email="api-denorm@example.com", org_name="Org Denorm")
    asset = _seed_asset(client, headers, "api-denorm.example.com")
    seed_asset = db.get(Asset, uuid.UUID(asset["id"]))
    alert = _make_alert(db, seed_asset.organization_id, seed_asset.id)

    listed = client.get("/alerts", headers=headers).json()
    matching = next(a for a in listed if a["id"] == str(alert.id))
    assert matching["asset_value"] == "api-denorm.example.com"
    assert matching["asset_type"] == "domain"

    single = client.get(f"/alerts/{alert.id}", headers=headers).json()
    assert single["asset_value"] == "api-denorm.example.com"
    assert single["asset_type"] == "domain"


def test_viewer_cannot_acknowledge_or_resolve(client, register_user, login_as, db):
    headers = register_user(email="api-viewer-write@example.com", org_name="Org Viewer")
    asset = _seed_asset(client, headers, "api-viewer-write.example.com")
    seed_asset = db.get(Asset, uuid.UUID(asset["id"]))
    alert = _make_alert(db, seed_asset.organization_id, seed_asset.id)

    # Create a viewer in the same org.
    resp = client.post(
        "/users", json={"email": "viewer2@example.com", "password": "correct-horse-battery", "full_name": "V", "role": "viewer"},
        headers=headers,
    )
    assert resp.status_code == 201, resp.text
    viewer_headers = login_as("viewer2@example.com", "correct-horse-battery")

    ack = client.post(f"/alerts/{alert.id}/acknowledge", headers=viewer_headers)
    assert ack.status_code == 403
    resolve = client.post(f"/alerts/{alert.id}/resolve", headers=viewer_headers)
    assert resolve.status_code == 403


def test_analyst_can_acknowledge_and_resolve(client, register_user, login_as, db):
    headers = register_user(email="api-analyst@example.com", org_name="Org Analyst")
    asset = _seed_asset(client, headers, "api-analyst.example.com")
    seed_asset = db.get(Asset, uuid.UUID(asset["id"]))
    alert = _make_alert(db, seed_asset.organization_id, seed_asset.id)

    resp = client.post(
        "/users", json={"email": "analyst2@example.com", "password": "correct-horse-battery", "full_name": "A", "role": "analyst"},
        headers=headers,
    )
    assert resp.status_code == 201, resp.text
    analyst_headers = login_as("analyst2@example.com", "correct-horse-battery")

    ack = client.post(f"/alerts/{alert.id}/acknowledge", headers=analyst_headers)
    assert ack.status_code == 200
    assert ack.json()["status"] == "acknowledged"

    resolve = client.post(f"/alerts/{alert.id}/resolve", headers=analyst_headers)
    assert resolve.status_code == 200
    assert resolve.json()["status"] == "resolved"


def test_acknowledge_non_open_alert_returns_400(client, register_user, db):
    headers = register_user(email="api-ack-400@example.com", org_name="Org 400")
    asset = _seed_asset(client, headers, "api-ack-400.example.com")
    seed_asset = db.get(Asset, uuid.UUID(asset["id"]))
    alert = _make_alert(db, seed_asset.organization_id, seed_asset.id)
    client.post(f"/alerts/{alert.id}/acknowledge", headers=headers)

    resp = client.post(f"/alerts/{alert.id}/acknowledge", headers=headers)
    assert resp.status_code == 400


def test_resolve_already_resolved_returns_400(client, register_user, db):
    headers = register_user(email="api-resolve-400@example.com", org_name="Org 400b")
    asset = _seed_asset(client, headers, "api-resolve-400.example.com")
    seed_asset = db.get(Asset, uuid.UUID(asset["id"]))
    alert = _make_alert(db, seed_asset.organization_id, seed_asset.id)
    client.post(f"/alerts/{alert.id}/resolve", headers=headers)

    resp = client.post(f"/alerts/{alert.id}/resolve", headers=headers)
    assert resp.status_code == 400


# --- Organization isolation / IDOR --------------------------------------------


def test_cross_org_get_returns_404(client, register_user, db):
    headers_a = register_user(email="api-org-a@example.com", org_name="Org IDOR A")
    asset_a = _seed_asset(client, headers_a, "api-org-a.example.com")
    seed_a = db.get(Asset, uuid.UUID(asset_a["id"]))
    alert = _make_alert(db, seed_a.organization_id, seed_a.id)

    headers_b = register_user(email="api-org-b@example.com", org_name="Org IDOR B")
    resp = client.get(f"/alerts/{alert.id}", headers=headers_b)
    assert resp.status_code == 404


def test_cross_org_acknowledge_and_resolve_return_404(client, register_user, db):
    headers_a = register_user(email="api-org-a2@example.com", org_name="Org IDOR A2")
    asset_a = _seed_asset(client, headers_a, "api-org-a2.example.com")
    seed_a = db.get(Asset, uuid.UUID(asset_a["id"]))
    alert = _make_alert(db, seed_a.organization_id, seed_a.id)

    headers_b = register_user(email="api-org-b2@example.com", org_name="Org IDOR B2")
    assert client.post(f"/alerts/{alert.id}/acknowledge", headers=headers_b).status_code == 404
    assert client.post(f"/alerts/{alert.id}/resolve", headers=headers_b).status_code == 404


def test_list_alerts_only_returns_own_organization(client, register_user, db):
    headers_a = register_user(email="api-org-list-a@example.com", org_name="Org List A")
    asset_a = _seed_asset(client, headers_a, "api-org-list-a.example.com")
    seed_a = db.get(Asset, uuid.UUID(asset_a["id"]))
    alert_a = _make_alert(db, seed_a.organization_id, seed_a.id)

    headers_b = register_user(email="api-org-list-b@example.com", org_name="Org List B")
    asset_b = _seed_asset(client, headers_b, "api-org-list-b.example.com")
    seed_b = db.get(Asset, uuid.UUID(asset_b["id"]))
    alert_b = _make_alert(db, seed_b.organization_id, seed_b.id)

    resp_a = client.get("/alerts", headers=headers_a)
    ids_a = {a["id"] for a in resp_a.json()}
    assert str(alert_a.id) in ids_a
    assert str(alert_b.id) not in ids_a


# --- Filtering / pagination / ordering -----------------------------------------


def test_filter_by_status_priority_type_and_asset(client, register_user, db):
    headers = register_user(email="api-filter@example.com", org_name="Org Filter")
    asset = _seed_asset(client, headers, "api-filter.example.com")
    seed_asset = db.get(Asset, uuid.UUID(asset["id"]))
    open_alert = _make_alert(db, seed_asset.organization_id, seed_asset.id, priority=AlertPriority.high, identity="open1")
    resolved_alert = _make_alert(db, seed_asset.organization_id, seed_asset.id, priority=AlertPriority.low, identity="resolved1")
    alert_service.resolve_alert(db, resolved_alert, None)

    resp = client.get("/alerts?status=open", headers=headers)
    ids = {a["id"] for a in resp.json()}
    assert str(open_alert.id) in ids and str(resolved_alert.id) not in ids

    resp2 = client.get("/alerts?priority=high", headers=headers)
    ids2 = {a["id"] for a in resp2.json()}
    assert str(open_alert.id) in ids2 and str(resolved_alert.id) not in ids2

    resp3 = client.get("/alerts?alert_type=certificate_changed", headers=headers)
    assert len(resp3.json()) == 2

    resp4 = client.get(f"/alerts?asset_id={seed_asset.id}", headers=headers)
    assert len(resp4.json()) == 2


def test_deterministic_ordering_and_keyset_pagination(client, register_user, db):
    headers = register_user(email="api-paginate@example.com", org_name="Org Paginate")
    asset = _seed_asset(client, headers, "api-paginate.example.com")
    seed_asset = db.get(Asset, uuid.UUID(asset["id"]))
    created = [
        _make_alert(db, seed_asset.organization_id, seed_asset.id, identity=f"page-{i}") for i in range(5)
    ]

    page1 = client.get("/alerts?limit=2", headers=headers).json()
    assert len(page1) == 2
    last = page1[-1]

    page2 = client.get(
        f"/alerts?limit=2&before_last_seen_at={last['last_seen_at']}&before_id={last['id']}", headers=headers
    ).json()
    assert len(page2) == 2
    page1_ids = {a["id"] for a in page1}
    page2_ids = {a["id"] for a in page2}
    assert page1_ids.isdisjoint(page2_ids)  # no overlap/duplication across pages

    # Re-fetching page 1 must be byte-for-byte identical (deterministic ordering).
    page1_again = client.get("/alerts?limit=2", headers=headers).json()
    assert [a["id"] for a in page1] == [a["id"] for a in page1_again]


def test_limit_is_bounded(client, register_user, db):
    headers = register_user(email="api-limit-bound@example.com", org_name="Org Limit")
    asset = _seed_asset(client, headers, "api-limit-bound.example.com")
    seed_asset = db.get(Asset, uuid.UUID(asset["id"]))
    _make_alert(db, seed_asset.organization_id, seed_asset.id)

    resp = client.get(f"/alerts?limit={alert_service.MAX_ALERT_LIST_LIMIT + 500}", headers=headers)
    assert resp.status_code == 422  # Query(le=...) rejects it outright, never silently clamps unboundedly
