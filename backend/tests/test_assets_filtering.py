"""Step 9.13: server-side filtering/pagination added to GET /assets.
Purely additive -- a dedicated suite confirms every existing (pre-9.13)
caller's assumption (no `limit` passed => full unbounded, unfiltered
org-scoped list) still holds exactly, alongside the new opt-in behavior.
"""

import uuid

from app.models.asset import Asset
from app.models.user import User


def _create_asset(client, headers, asset_type, value):
    resp = client.post("/assets", json={"asset_type": asset_type, "value": value}, headers=headers)
    assert resp.status_code == 201, resp.text
    return resp.json()


def test_no_limit_returns_full_unbounded_list_backward_compatible(client, register_user):
    headers = register_user(email="filt-unbounded@example.com")
    for i in range(5):
        _create_asset(client, headers, "domain", f"unbounded-{i}.example.com")

    resp = client.get("/assets", headers=headers)
    assert resp.status_code == 200
    assert len(resp.json()) == 5


def test_default_ordering_is_deterministic_by_value(client, register_user):
    headers = register_user(email="filt-order@example.com")
    _create_asset(client, headers, "domain", "zebra.example.com")
    _create_asset(client, headers, "domain", "alpha.example.com")
    _create_asset(client, headers, "domain", "mid.example.com")

    resp = client.get("/assets", headers=headers).json()
    values = [a["value"] for a in resp]
    assert values == sorted(values)


def test_filter_by_asset_type(client, register_user):
    headers = register_user(email="filt-type@example.com")
    _create_asset(client, headers, "domain", "filt-type-domain.example.com")
    _create_asset(client, headers, "ip_address", "93.184.216.70")

    resp = client.get("/assets?asset_type=ip_address", headers=headers).json()
    assert len(resp) == 1
    assert resp[0]["asset_type"] == "ip_address"


def test_filter_by_status(client, register_user, db):
    headers = register_user(email="filt-status@example.com")
    asset = _create_asset(client, headers, "domain", "filt-status.example.com")
    db_asset = db.get(Asset, uuid.UUID(asset["id"]))
    db_asset.status = "stale"
    db.commit()

    resp_active = client.get("/assets?status=active", headers=headers).json()
    resp_stale = client.get("/assets?status=stale", headers=headers).json()
    assert resp_active == []
    assert len(resp_stale) == 1


def test_filter_by_environment_and_criticality(client, register_user, db):
    headers = register_user(email="filt-env-crit@example.com")
    asset = _create_asset(client, headers, "domain", "filt-env-crit.example.com")
    _create_asset(client, headers, "domain", "filt-env-crit-other.example.com")
    db_asset = db.get(Asset, uuid.UUID(asset["id"]))
    db_asset.environment = "production"
    db_asset.criticality = "critical"
    db.commit()

    resp = client.get("/assets?environment=production&criticality=critical", headers=headers).json()
    assert len(resp) == 1
    assert resp[0]["id"] == asset["id"]


def test_search_is_case_insensitive_substring(client, register_user):
    headers = register_user(email="filt-search@example.com")
    _create_asset(client, headers, "domain", "search-target.example.com")
    _create_asset(client, headers, "domain", "unrelated.example.org")

    resp = client.get("/assets?search=SEARCH-TARGET", headers=headers).json()
    assert len(resp) == 1
    assert resp[0]["value"] == "search-target.example.com"


def test_limit_bounds_result_and_keyset_pagination_pages_forward(client, register_user):
    headers = register_user(email="filt-page@example.com")
    for i in range(5):
        _create_asset(client, headers, "domain", f"page-{i}.example.com")

    page1 = client.get("/assets?limit=2", headers=headers).json()
    assert len(page1) == 2
    last = page1[-1]

    page2 = client.get(
        f"/assets?limit=2&after_value={last['value']}&after_id={last['id']}", headers=headers
    ).json()
    assert len(page2) == 2
    page1_ids = {a["id"] for a in page1}
    page2_ids = {a["id"] for a in page2}
    assert page1_ids.isdisjoint(page2_ids)


def test_limit_exceeding_max_is_rejected(client, register_user):
    headers = register_user(email="filt-limit-max@example.com")
    resp = client.get("/assets?limit=9999", headers=headers)
    assert resp.status_code == 422


def test_filters_are_organization_scoped(client, register_user):
    headers_a = register_user(email="filt-org-a@example.com", org_name="Filt Org A")
    headers_b = register_user(email="filt-org-b@example.com", org_name="Filt Org B")
    _create_asset(client, headers_a, "domain", "filt-org-a.example.com")
    _create_asset(client, headers_b, "domain", "filt-org-b.example.com")

    resp_a = client.get("/assets?search=filt-org", headers=headers_a).json()
    assert len(resp_a) == 1
    assert resp_a[0]["value"] == "filt-org-a.example.com"
