"""Tests for graph_service.get_attack_surface_summary and GET /assets/summary."""

import uuid

from app.core.enums import AssetCriticality
from app.models.asset import Asset


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


def _link(client, headers, source_id, target_id, relationship_type="related_to"):
    resp = client.post(
        f"/assets/{source_id}/relationships",
        json={"target_asset_id": target_id, "relationship_type": relationship_type},
        headers=headers,
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def test_empty_organization_summary(client, register_user):
    headers = register_user()

    resp = client.get("/assets/summary", headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["total_assets"] == 0
    assert body["assets_by_type"] == {}
    assert body["assets_by_status"] == {}
    assert body["assets_by_criticality"] == {}
    assert body["total_relationships"] == 0
    assert body["relationships_by_type"] == {}
    assert body["total_observations"] == 0
    assert body["recent_observations_last_7_days"] == 0
    assert body["isolated_asset_count"] == 0


def test_total_asset_count(client, register_user):
    headers = register_user()
    _create_and_authorize_asset(client, headers, "summary-count-a.example.com")
    _create_and_authorize_asset(client, headers, "summary-count-b.example.com")

    resp = client.get("/assets/summary", headers=headers)
    assert resp.json()["total_assets"] == 2


def test_asset_type_aggregation(client, register_user):
    headers = register_user()
    _create_and_authorize_asset(client, headers, "summary-type.example.com", asset_type="domain")
    _create_and_authorize_asset(client, headers, "93.184.216.90", asset_type="ip_address")

    resp = client.get("/assets/summary", headers=headers)
    by_type = resp.json()["assets_by_type"]
    assert by_type["domain"] == 1
    assert by_type["ip_address"] == 1


def test_asset_status_aggregation(client, register_user):
    headers = register_user()
    _create_and_authorize_asset(client, headers, "summary-status.example.com")

    resp = client.get("/assets/summary", headers=headers)
    by_status = resp.json()["assets_by_status"]
    assert by_status["active"] == 1  # manually created assets default to active


def test_asset_criticality_aggregation(client, register_user, db):
    headers = register_user()
    asset = _create_and_authorize_asset(client, headers, "summary-criticality.example.com")
    _create_and_authorize_asset(client, headers, "summary-no-criticality.example.com")

    db_asset = db.get(Asset, uuid.UUID(asset["id"]))
    db_asset.criticality = AssetCriticality.high
    db.commit()

    resp = client.get("/assets/summary", headers=headers)
    body = resp.json()
    assert body["assets_by_criticality"] == {"high": 1}  # the unset one is excluded, not counted as "none"
    assert body["total_assets"] == 2


def test_relationship_aggregation(client, register_user):
    headers = register_user()
    a = _create_and_authorize_asset(client, headers, "summary-rel-a.example.com")
    b = _create_and_authorize_asset(client, headers, "summary-rel-b.example.com")
    c = _create_and_authorize_asset(client, headers, "summary-rel-c.example.com")
    _link(client, headers, a["id"], b["id"], relationship_type="related_to")
    _link(client, headers, a["id"], c["id"], relationship_type="uses")

    resp = client.get("/assets/summary", headers=headers)
    body = resp.json()
    assert body["total_relationships"] == 2
    assert body["relationships_by_type"] == {"related_to": 1, "uses": 1}


def test_observation_and_recent_change_counts(client, register_user):
    headers = register_user()
    a = _create_and_authorize_asset(client, headers, "summary-obs-a.example.com")
    b = _create_and_authorize_asset(client, headers, "summary-obs-b.example.com")
    _link(client, headers, a["id"], b["id"])

    resp = client.get("/assets/summary", headers=headers)
    body = resp.json()
    # 2 asset_created + 1 relationship_created, all just happened -> all recent
    assert body["total_observations"] >= 3
    assert body["recent_observations_last_7_days"] == body["total_observations"]


def test_isolated_asset_count(client, register_user):
    headers = register_user()
    a = _create_and_authorize_asset(client, headers, "summary-isolated-a.example.com")
    b = _create_and_authorize_asset(client, headers, "summary-isolated-b.example.com")
    _create_and_authorize_asset(client, headers, "summary-isolated-c.example.com")  # stays isolated
    _link(client, headers, a["id"], b["id"])

    resp = client.get("/assets/summary", headers=headers)
    assert resp.json()["isolated_asset_count"] == 1


def test_response_does_not_contain_a_risk_score_field(client, register_user):
    headers = register_user()
    _create_and_authorize_asset(client, headers, "summary-no-risk.example.com")

    resp = client.get("/assets/summary", headers=headers)
    body = resp.json()
    forbidden_keys = {"risk_score", "risk", "severity", "score"}
    assert forbidden_keys.isdisjoint(body.keys())


def test_organization_isolation(client, register_user):
    org_a_headers = register_user(org_name="Summary Org A", email="summary-org-a@example.com")
    org_b_headers = register_user(org_name="Summary Org B", email="summary-org-b@example.com")
    _create_and_authorize_asset(client, org_a_headers, "summary-iso-a.example.com")
    _create_and_authorize_asset(client, org_b_headers, "summary-iso-b1.example.com")
    _create_and_authorize_asset(client, org_b_headers, "summary-iso-b2.example.com")

    resp_a = client.get("/assets/summary", headers=org_a_headers)
    assert resp_a.json()["total_assets"] == 1


def test_all_authenticated_roles_can_read_summary(client, register_user, login_as):
    admin_headers = register_user(email="summary-role-admin@example.com")
    _create_and_authorize_asset(client, admin_headers, "summary-role.example.com")

    for role, email in (("analyst", "summary-role-analyst@example.com"), ("viewer", "summary-role-viewer@example.com")):
        resp = client.post(
            "/users",
            json={"email": email, "password": "correct-horse-battery", "full_name": role, "role": role},
            headers=admin_headers,
        )
        assert resp.status_code == 201
        role_headers = login_as(email, "correct-horse-battery")
        role_resp = client.get("/assets/summary", headers=role_headers)
        assert role_resp.status_code == 200
