"""Tests for graph_service.get_activity_feed and GET /assets/activity."""

import time
import uuid
from datetime import datetime, timedelta, timezone

from app.core.enums import AssetSource, ChangeType
from app.models.observation import Observation
from app.services import graph_service


def _create_and_authorize_asset(client, headers, value, asset_type="domain"):
    resp = client.post("/assets", json={"asset_type": asset_type, "value": value}, headers=headers)
    assert resp.status_code == 201, resp.text
    asset = resp.json()
    confirm = client.post(
        f"/assets/{asset['id']}/confirm-authorization",
        json={"authorization_confirmed": True},
        headers=headers,
    )
    assert confirm.status_code == 200, confirm.text
    return asset


def test_empty_organization_returns_empty_feed(client, register_user):
    headers = register_user()

    resp = client.get("/assets/activity", headers=headers)
    assert resp.status_code == 200
    assert resp.json() == []


def test_asset_creation_appears_in_feed(client, register_user):
    headers = register_user()
    asset = _create_and_authorize_asset(client, headers, "activity-basic.example.com")

    resp = client.get("/assets/activity", headers=headers)
    body = resp.json()
    change_types = [item["change_type"] for item in body if item["asset_id"] == asset["id"]]
    assert "asset_created" in change_types


def test_feed_item_carries_asset_context_without_a_second_request(client, register_user):
    headers = register_user()
    asset = _create_and_authorize_asset(client, headers, "activity-context.example.com")

    resp = client.get("/assets/activity", headers=headers)
    item = next(i for i in resp.json() if i["asset_id"] == asset["id"] and i["change_type"] == "asset_created")
    assert item["asset_type"] == "domain"
    assert item["asset_value"] == "activity-context.example.com"
    assert item["source"] == "manual"
    assert "confidence" in item
    assert "observed_at" in item


def test_newest_first_ordering(client, register_user, db):
    headers = register_user()
    asset = _create_and_authorize_asset(client, headers, "activity-order.example.com")
    asset_uuid = uuid.UUID(asset["id"])

    base = datetime.now(timezone.utc)
    for i in range(3):
        db.add(
            Observation(
                asset_id=asset_uuid,
                change_type=ChangeType.asset_updated,
                field_name=f"seq-{i}",
                current_value=str(i),
                observed_at=base + timedelta(seconds=i),
                source=AssetSource.discovery,
                confidence=1.0,
            )
        )
    db.commit()

    resp = client.get("/assets/activity", headers=headers)
    ours = [item for item in resp.json() if item["field_name"] in {"seq-0", "seq-1", "seq-2"}]
    assert [item["field_name"] for item in ours] == ["seq-2", "seq-1", "seq-0"]


def test_same_timestamp_ordering_is_deterministic_by_id(client, register_user, db):
    headers = register_user()
    asset = _create_and_authorize_asset(client, headers, "activity-tie.example.com")
    asset_uuid = uuid.UUID(asset["id"])

    same_time = datetime.now(timezone.utc)
    ids = []
    for i in range(3):
        obs = Observation(
            asset_id=asset_uuid,
            change_type=ChangeType.asset_updated,
            field_name=f"tie-{i}",
            current_value=str(i),
            observed_at=same_time,
            source=AssetSource.discovery,
            confidence=1.0,
        )
        db.add(obs)
        db.flush()
        ids.append(obs.id)
    db.commit()

    expected_field_order = [f"tie-{i}" for i, _ in sorted(enumerate(ids), key=lambda pair: pair[1], reverse=True)]

    resp = client.get("/assets/activity", headers=headers)
    ours = [item for item in resp.json() if item["field_name"] in {"tie-0", "tie-1", "tie-2"}]
    assert [item["field_name"] for item in ours] == expected_field_order

    # Calling twice must produce the identical order -- proving this
    # isn't an accident of one query plan's incidental row order.
    resp2 = client.get("/assets/activity", headers=headers)
    ours2 = [item for item in resp2.json() if item["field_name"] in {"tie-0", "tie-1", "tie-2"}]
    assert [item["field_name"] for item in ours2] == expected_field_order


def test_since_filter_excludes_older_observations(client, register_user, db):
    headers = register_user()
    asset = _create_and_authorize_asset(client, headers, "activity-since.example.com")
    asset_uuid = uuid.UUID(asset["id"])

    old = datetime.now(timezone.utc) - timedelta(days=10)
    db.add(
        Observation(
            asset_id=asset_uuid, change_type=ChangeType.asset_updated, field_name="old-event",
            current_value="x", observed_at=old, source=AssetSource.discovery, confidence=1.0,
        )
    )
    db.commit()

    cutoff = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    resp = client.get("/assets/activity", params={"since": cutoff}, headers=headers)
    assert resp.status_code == 200, resp.text
    field_names = [item["field_name"] for item in resp.json()]
    assert "old-event" not in field_names


def test_change_type_filter(client, register_user, db):
    headers = register_user()
    asset = _create_and_authorize_asset(client, headers, "activity-changetype.example.com")
    asset_uuid = uuid.UUID(asset["id"])

    db.add(
        Observation(
            asset_id=asset_uuid, change_type=ChangeType.dns_records_observed, field_name="dns-marker",
            current_value="x", source=AssetSource.discovery, confidence=1.0,
        )
    )
    db.commit()

    resp = client.get("/assets/activity?change_type=dns_records_observed", headers=headers)
    body = resp.json()
    assert all(item["change_type"] == "dns_records_observed" for item in body)
    assert any(item["field_name"] == "dns-marker" for item in body)


def test_limit_is_respected(client, register_user, db):
    headers = register_user()
    asset = _create_and_authorize_asset(client, headers, "activity-limit.example.com")
    asset_uuid = uuid.UUID(asset["id"])

    for i in range(10):
        db.add(
            Observation(
                asset_id=asset_uuid, change_type=ChangeType.asset_updated, field_name=f"limit-{i}",
                current_value=str(i), source=AssetSource.discovery, confidence=1.0,
            )
        )
    db.commit()

    resp = client.get("/assets/activity?limit=3", headers=headers)
    assert len(resp.json()) == 3


def test_limit_exceeding_maximum_is_rejected(client, register_user):
    headers = register_user()
    resp = client.get(f"/assets/activity?limit={graph_service.MAX_ACTIVITY_LIMIT + 1}", headers=headers)
    assert resp.status_code == 422  # FastAPI's own Query(le=) validation, not manually re-implemented


def test_service_function_caps_limit_defensively(client, register_user, db):
    """Even if a caller bypasses the route's own Query validation and
    calls the service function directly with an oversized limit, it
    must still be capped -- defense in depth against an unbounded query.
    """
    headers = register_user()
    asset = _create_and_authorize_asset(client, headers, "activity-defensive-limit.example.com")
    org_id = uuid.UUID(asset["organization_id"])

    entries = graph_service.get_activity_feed(db, org_id, limit=100_000)
    assert len(entries) <= graph_service.MAX_ACTIVITY_LIMIT


def test_organization_isolation(client, register_user):
    org_a_headers = register_user(org_name="Activity Org A", email="activity-org-a@example.com")
    org_b_headers = register_user(org_name="Activity Org B", email="activity-org-b@example.com")
    _create_and_authorize_asset(client, org_a_headers, "activity-iso-a.example.com")
    _create_and_authorize_asset(client, org_b_headers, "activity-iso-b.example.com")

    resp_a = client.get("/assets/activity", headers=org_a_headers)
    values_a = {item["asset_value"] for item in resp_a.json()}
    assert "activity-iso-a.example.com" in values_a
    assert "activity-iso-b.example.com" not in values_a


def test_all_authenticated_roles_can_read_activity_feed(client, register_user, login_as):
    admin_headers = register_user(email="activity-role-admin@example.com")
    _create_and_authorize_asset(client, admin_headers, "activity-role.example.com")

    for role, email in (("analyst", "activity-role-analyst@example.com"), ("viewer", "activity-role-viewer@example.com")):
        resp = client.post(
            "/users",
            json={"email": email, "password": "correct-horse-battery", "full_name": role, "role": role},
            headers=admin_headers,
        )
        assert resp.status_code == 201
        role_headers = login_as(email, "correct-horse-battery")
        role_resp = client.get("/assets/activity", headers=role_headers)
        assert role_resp.status_code == 200


# --- Step 9.9.7: asset_type filter and keyset pagination --------------------


def test_asset_type_filter(client, register_user):
    headers = register_user()
    _create_and_authorize_asset(client, headers, "activity-type-domain.example.com", asset_type="domain")
    _create_and_authorize_asset(client, headers, "93.184.216.98", asset_type="ip_address")

    resp = client.get("/assets/activity?asset_type=ip_address", headers=headers)
    body = resp.json()
    assert all(item["asset_type"] == "ip_address" for item in body)
    assert any(item["asset_value"] == "93.184.216.98" for item in body)
    assert all(item["asset_value"] != "activity-type-domain.example.com" for item in body)


def test_keyset_pagination_pages_through_full_result_set_without_gaps_or_overlap(client, register_user, db):
    headers = register_user()
    asset = _create_and_authorize_asset(client, headers, "activity-page.example.com")
    asset_uuid = uuid.UUID(asset["id"])

    base = datetime.now(timezone.utc)
    for i in range(7):
        db.add(
            Observation(
                asset_id=asset_uuid, change_type=ChangeType.asset_updated, field_name=f"page-{i}",
                current_value=str(i), observed_at=base + timedelta(seconds=i),
                source=AssetSource.discovery, confidence=1.0,
            )
        )
    db.commit()

    seen_field_names = []
    cursor_observed_at = None
    cursor_id = None
    for _ in range(20):  # generous upper bound on pages; loop breaks itself
        params = {"limit": 3}
        if cursor_observed_at is not None:
            params["before_observed_at"] = cursor_observed_at
            params["before_id"] = cursor_id
        resp = client.get("/assets/activity", params=params, headers=headers)
        assert resp.status_code == 200
        page = resp.json()
        if not page:
            break
        seen_field_names.extend(item["field_name"] for item in page if item["field_name"] and item["field_name"].startswith("page-"))
        cursor_observed_at = page[-1]["observed_at"]
        cursor_id = page[-1]["id"]

    expected = [f"page-{i}" for i in range(6, -1, -1)]
    assert seen_field_names == expected  # every "page-*" item seen exactly once, in the correct order, no gaps or overlap


def test_pagination_cursor_requires_both_parameters_together(client, register_user):
    """Passing only one of before_observed_at/before_id is a no-op filter
    (documented behavior, not an error) -- this test pins that down so
    a future change to the pairing logic doesn't silently break it.
    """
    headers = register_user()
    _create_and_authorize_asset(client, headers, "activity-partial-cursor.example.com")

    resp = client.get("/assets/activity?before_id=" + str(uuid.uuid4()), headers=headers)
    assert resp.status_code == 200
    assert len(resp.json()) >= 1
