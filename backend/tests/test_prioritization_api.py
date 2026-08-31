"""API-level tests for GET /assets/prioritized and GET /assets/{id}/risk:
organization isolation, RBAC, IDOR, pagination, filtering, deterministic
ordering, and consistency between the two endpoints. The underlying
scoring logic itself is exhaustively covered by test_prioritization.py.
"""

import uuid

from app.core.enums import AssetCriticality
from app.models.asset import Asset


def _create_and_authorize_asset(client, headers, value, asset_type="domain"):
    resp = client.post("/assets", json={"asset_type": asset_type, "value": value}, headers=headers)
    assert resp.status_code == 201, resp.text
    asset = resp.json()
    confirm = client.post(
        f"/assets/{asset['id']}/confirm-authorization", json={"authorization_confirmed": True}, headers=headers
    )
    assert confirm.status_code == 200, confirm.text
    return asset


def test_prioritized_endpoint_requires_authentication(client):
    resp = client.get("/assets/prioritized")
    assert resp.status_code == 401


def test_risk_endpoint_requires_authentication(client):
    resp = client.get(f"/assets/{uuid.uuid4()}/risk")
    assert resp.status_code == 401


def test_prioritized_returns_expected_shape(client, register_user):
    headers = register_user()
    _create_and_authorize_asset(client, headers, "prio-api-shape.example.com")

    resp = client.get("/assets/prioritized", headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert len(body) == 1
    item = body[0]
    assert set(item.keys()) == {
        "asset_id", "asset_type", "asset_value", "priority", "confidence_label",
        "confidence_value", "dimensions", "reasons", "evaluated_at",
    }
    assert set(item["dimensions"].keys()) == {
        "exposure", "business_criticality", "change_recency", "connectivity_relevance", "evidence_confidence",
    }


def test_organization_isolation_prioritized(client, register_user):
    org_a_headers = register_user(org_name="Prio API Org A", email="prio-api-org-a@example.com")
    org_b_headers = register_user(org_name="Prio API Org B", email="prio-api-org-b@example.com")
    _create_and_authorize_asset(client, org_a_headers, "prio-api-iso-a.example.com")
    _create_and_authorize_asset(client, org_b_headers, "prio-api-iso-b.example.com")

    resp_a = client.get("/assets/prioritized", headers=org_a_headers).json()
    values_a = {item["asset_value"] for item in resp_a}
    assert "prio-api-iso-a.example.com" in values_a
    assert "prio-api-iso-b.example.com" not in values_a


def test_idor_cross_organization_asset_risk_returns_404(client, register_user):
    org_a_headers = register_user(org_name="Prio IDOR Org A", email="prio-idor-a@example.com")
    org_b_headers = register_user(org_name="Prio IDOR Org B", email="prio-idor-b@example.com")
    asset_b = _create_and_authorize_asset(client, org_b_headers, "prio-idor-b.example.com")

    resp = client.get(f"/assets/{asset_b['id']}/risk", headers=org_a_headers)
    assert resp.status_code == 404


def test_risk_endpoint_unknown_asset_id_returns_404(client, register_user):
    headers = register_user()
    resp = client.get(f"/assets/{uuid.uuid4()}/risk", headers=headers)
    assert resp.status_code == 404


def test_all_authenticated_roles_can_read_prioritized(client, register_user, login_as):
    admin_headers = register_user(email="prio-role-admin@example.com")
    _create_and_authorize_asset(client, admin_headers, "prio-role.example.com")

    for role, email in (("analyst", "prio-role-analyst@example.com"), ("viewer", "prio-role-viewer@example.com")):
        resp = client.post(
            "/users",
            json={"email": email, "password": "correct-horse-battery", "full_name": role, "role": role},
            headers=admin_headers,
        )
        assert resp.status_code == 201
        role_headers = login_as(email, "correct-horse-battery")
        role_resp = client.get("/assets/prioritized", headers=role_headers)
        assert role_resp.status_code == 200
        risk_resp = client.get("/assets/prioritized", headers=role_headers)
        assert risk_resp.status_code == 200


def test_pagination_limit_is_respected(client, register_user):
    headers = register_user()
    for i in range(5):
        _create_and_authorize_asset(client, headers, f"prio-page-{i}.example.com")

    resp = client.get("/assets/prioritized?limit=2", headers=headers)
    assert resp.status_code == 200
    assert len(resp.json()) == 2


def test_limit_exceeding_maximum_is_rejected(client, register_user):
    headers = register_user()
    resp = client.get("/assets/prioritized?limit=500", headers=headers)
    assert resp.status_code == 422


def test_filter_by_asset_type(client, register_user):
    headers = register_user()
    _create_and_authorize_asset(client, headers, "prio-filter-domain.example.com", asset_type="domain")
    _create_and_authorize_asset(client, headers, "93.184.216.101", asset_type="ip_address")

    resp = client.get("/assets/prioritized?asset_type=ip_address", headers=headers)
    body = resp.json()
    assert all(item["asset_type"] == "ip_address" for item in body)
    assert any(item["asset_value"] == "93.184.216.101" for item in body)


def test_filter_by_environment(client, register_user, db):
    headers = register_user()
    a = _create_and_authorize_asset(client, headers, "prio-filter-env-a.example.com")
    b = _create_and_authorize_asset(client, headers, "prio-filter-env-b.example.com")
    asset_b = db.get(Asset, uuid.UUID(b["id"]))
    from app.core.enums import AssetEnvironment

    asset_b.environment = AssetEnvironment.production
    db.commit()

    resp = client.get("/assets/prioritized?environment=production", headers=headers)
    values = {item["asset_value"] for item in resp.json()}
    assert "prio-filter-env-b.example.com" in values
    assert "prio-filter-env-a.example.com" not in values


def test_filter_by_criticality(client, register_user, db):
    headers = register_user()
    a = _create_and_authorize_asset(client, headers, "prio-filter-crit-a.example.com")
    b = _create_and_authorize_asset(client, headers, "prio-filter-crit-b.example.com")
    asset_b = db.get(Asset, uuid.UUID(b["id"]))
    asset_b.criticality = AssetCriticality.critical
    db.commit()

    resp = client.get("/assets/prioritized?criticality=critical", headers=headers)
    values = {item["asset_value"] for item in resp.json()}
    assert "prio-filter-crit-b.example.com" in values
    assert "prio-filter-crit-a.example.com" not in values


def test_filter_by_priority(client, register_user, db):
    headers = register_user()
    high = _create_and_authorize_asset(client, headers, "93.184.216.102", asset_type="ip_address")
    low = _create_and_authorize_asset(client, headers, "AS64999", asset_type="asn")

    high_asset = db.get(Asset, uuid.UUID(high["id"]))
    high_asset.criticality = AssetCriticality.critical
    db.commit()

    # Fetch unfiltered first to discover the actual computed priority for
    # each, then filter to just that value and confirm scoping works.
    unfiltered = {item["asset_value"]: item["priority"] for item in client.get("/assets/prioritized", headers=headers).json()}
    target_priority = unfiltered["93.184.216.102"]

    resp = client.get(f"/assets/prioritized?priority={target_priority}", headers=headers)
    body = resp.json()
    assert all(item["priority"] == target_priority for item in body)
    assert any(item["asset_value"] == "93.184.216.102" for item in body)


def test_deterministic_ordering_priority_then_value(client, register_user, db):
    headers = register_user()
    b_value = "prio-order-b.example.com"
    a_value = "prio-order-a.example.com"
    _create_and_authorize_asset(client, headers, b_value)
    _create_and_authorize_asset(client, headers, a_value)

    first = client.get("/assets/prioritized", headers=headers).json()
    second = client.get("/assets/prioritized", headers=headers).json()
    assert [item["asset_value"] for item in first] == [item["asset_value"] for item in second]
    # Both are equal priority (no distinguishing signals) -- alphabetical tiebreaker.
    ours = [item["asset_value"] for item in first if item["asset_value"] in (a_value, b_value)]
    assert ours == [a_value, b_value]


def test_prioritized_list_and_single_asset_risk_endpoint_agree(client, register_user, db):
    headers = register_user()
    asset = _create_and_authorize_asset(client, headers, "prio-agree.example.com")
    db_asset = db.get(Asset, uuid.UUID(asset["id"]))
    db_asset.criticality = AssetCriticality.high
    db.commit()

    list_item = next(
        item for item in client.get("/assets/prioritized", headers=headers).json() if item["asset_value"] == "prio-agree.example.com"
    )
    single_item = client.get(f"/assets/{asset['id']}/risk", headers=headers).json()

    assert list_item["priority"] == single_item["priority"]
    assert list_item["dimensions"] == single_item["dimensions"]
    assert [r["signal"] for r in list_item["reasons"]] == [r["signal"] for r in single_item["reasons"]]


def test_empty_organization_returns_empty_list(client, register_user):
    headers = register_user()
    resp = client.get("/assets/prioritized", headers=headers)
    assert resp.status_code == 200
    assert resp.json() == []
