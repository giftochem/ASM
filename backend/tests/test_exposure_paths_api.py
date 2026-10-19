"""Stage B: GET /assets/exposure-paths -- the read-only API over the
Exposure Path Engine. Evidence is written relative to the real current
time, since the endpoint's default (and latest allowed) assessment time
is now."""

import uuid
from datetime import datetime, timedelta, timezone

import pytest

from app.core.enums import AssetCriticality, AssetType
from app.models.asset import Asset
from app.models.audit_log import AuditLog
from app.models.discovery_run import DiscoveryRun
from app.models.observation import Observation
from app.models.organization import Organization
from app.models.scan import Scan
from app.models.user import User
from app.services import attack_path_service as engine
from tests.attack_path_fixtures import http_result, make_asset, observed_dns

PASSWORD = "correct-horse-battery"
URL = "/assets/exposure-paths"


def _now():
    return datetime.now(timezone.utc)


def _org_and_user(db, email):
    user = db.query(User).filter(User.email == email).one()
    return db.get(Organization, user.organization_id), user


def _add_user(client, admin_headers, login_as, email, role):
    resp = client.post(
        "/users", json={"email": email, "password": PASSWORD, "full_name": role.title(), "role": role}, headers=admin_headers
    )
    assert resp.status_code == 201, resp.text
    return login_as(email, PASSWORD)


def _graph(db, org, user, *, evidence_at):
    """One exposed site resolving (observed DNS) to a critical database IP,
    plus an exposed high-criticality app: two paths."""
    site = make_asset(db, org, "site.example.com")
    database = make_asset(db, org, "198.51.100.90", AssetType.ip_address, criticality=AssetCriticality.critical)
    app = make_asset(db, org, "app.example.com", criticality=AssetCriticality.high)
    http_result(db, org, user, site, "https", at=evidence_at)
    http_result(db, org, user, app, "https", at=evidence_at)
    relationship = observed_dns(db, org, user, site, database, at=evidence_at)
    db.flush()
    return {"site": site, "database": database, "app": app, "relationship": relationship}


@pytest.fixture
def admin(client, register_user, db):
    headers = register_user(email="paths-admin@example.com", org_name="Paths Org")
    org, user = _org_and_user(db, "paths-admin@example.com")
    return headers, org, user


# --- 22-23. Access ---------------------------------------------------------------------


@pytest.mark.parametrize("role", ["admin", "analyst", "viewer"])
def test_every_role_can_read_its_organizations_paths(client, login_as, db, admin, role):
    admin_headers, org, user = admin
    _graph(db, org, user, evidence_at=_now() - timedelta(hours=2))
    headers = admin_headers if role == "admin" else _add_user(client, admin_headers, login_as, f"paths-{role}@example.com", role)

    resp = client.get(URL, headers=headers)

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["organization_id"] == str(org.id) and body["path_count"] == 2


def test_unauthenticated_request_is_rejected(client):
    assert client.get(URL).status_code == 401


# --- 21. Validation ----------------------------------------------------------------------


@pytest.mark.parametrize(
    "params",
    [{"max_hops": -1}, {"max_hops": 4}, {"max_targets": 0}, {"max_targets": 26}, {"max_paths": 0},
     {"max_paths": 101}, {"max_nodes": 0}, {"max_nodes": 501}],
)
def test_out_of_range_limits_are_400(client, admin, params):
    headers, _, _ = admin

    resp = client.get(URL, params=params, headers=headers)

    assert resp.status_code == 400
    assert "must be between" in resp.json()["detail"] and next(iter(params)) in resp.json()["detail"]


def test_every_bad_limit_is_named(client, admin):
    headers, _, _ = admin

    detail = client.get(URL, params={"max_hops": 9, "max_nodes": -5}, headers=headers).json()["detail"]

    assert "max_hops" in detail and "max_nodes" in detail


@pytest.mark.parametrize("params", [{"max_hops": "three"}, {"max_paths": "1.5"}, {"as_of": "yesterday"}])
def test_malformed_values_are_422(client, admin, params):
    headers, _, _ = admin

    assert client.get(URL, params=params, headers=headers).status_code == 422


@pytest.mark.parametrize(
    "as_of,message",
    [("2026-10-19T12:00:00", "timezone"), ((_now() + timedelta(days=1)).isoformat(), "future")],
)
def test_invalid_assessment_times_are_400(client, admin, as_of, message):
    headers, _, _ = admin

    resp = client.get(URL, params={"as_of": as_of}, headers=headers)

    assert resp.status_code == 400 and message in resp.json()["detail"]


def test_explicit_assessment_time_is_point_in_time(client, db, admin):
    headers, org, user = admin
    evidence_at = _now() - timedelta(hours=2)
    _graph(db, org, user, evidence_at=evidence_at)

    before = client.get(URL, params={"as_of": (evidence_at - timedelta(hours=1)).isoformat()}, headers=headers).json()
    after = client.get(URL, params={"as_of": (evidence_at + timedelta(hours=1)).isoformat()}, headers=headers).json()
    much_later = client.get(URL, params={"as_of": (evidence_at + timedelta(days=8)).isoformat()}, headers=headers)

    assert before["path_count"] == 0 and after["path_count"] == 2
    assert after["assessed_at"].startswith((evidence_at + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M"))
    assert much_later.status_code == 400  # in the future


def test_limits_are_applied_and_reported(client, db, admin):
    headers, org, user = admin
    _graph(db, org, user, evidence_at=_now() - timedelta(hours=2))

    body = client.get(URL, params={"max_paths": 1, "max_hops": 1}, headers=headers).json()

    assert body["limits"] == {"max_hops": 1, "max_targets": 25, "max_paths": 1, "max_nodes": 500}
    assert body["path_count"] == 1 and body["truncated"] is True
    assert [reason["limit"] for reason in body["truncation_reasons"]] == ["max_paths"]


# --- 26. Contract, interpretation and disclaimer --------------------------------------------


def test_response_contract(client, db, admin):
    headers, org, user = admin
    graph = _graph(db, org, user, evidence_at=_now() - timedelta(hours=2))

    body = client.get(URL, headers=headers).json()

    assert body["disclaimer"] == "Observed exposure paths; exploitability not assessed."
    assert body["freshness_window_seconds"] == 7 * 24 * 3600
    assert body["limits"] == {"max_hops": 3, "max_targets": 25, "max_paths": 100, "max_nodes": 500}
    assert (body["eligible_target_count"], body["examined_target_count"], body["entry_point_count"]) == (2, 2, 2)
    assert body["truncated"] is False and body["truncation_reasons"] == []
    assert body["limitations"]

    dns_path, zero_hop = body["paths"]  # critical target first
    assert dns_path["hop_count"] == 1 and dns_path["is_zero_hop"] is False
    assert dns_path["basis"] == "observed_dns_association"
    assert dns_path["entry_point"] == {
        "asset_id": str(graph["site"].id), "asset_type": "domain", "value": "site.example.com",
        "criticality": None, "environment": None,
    }
    assert dns_path["target"]["criticality"] == "critical" and dns_path["target"]["asset_id"] == str(graph["database"].id)
    assert [node["value"] for node in dns_path["nodes"]] == ["site.example.com", "198.51.100.90"]
    (step,) = dns_path["steps"]
    assert step["relationship_id"] == str(graph["relationship"].id) and step["relationship_type"] == "resolves_to"
    assert step["direction"] == "forward" and step["basis"] == "observed_dns_association"
    assert step["relationship_source"] == "discovery" and step["analyst_assertion"] is None
    assert step["dns_evidence"]["freshness"] == "current" and step["dns_evidence"]["record_type"] == "A"
    (evidence,) = dns_path["entry_evidence"]
    assert evidence["evidence_type"] == "http_response" and evidence["freshness"] == "current"
    assert evidence["result_id"] and evidence["discovery_run_id"]
    assert dns_path["interpretation"].startswith("Observed infrastructure association")
    for path in body["paths"]:
        assert path["limitations"][0] == engine.NOT_ASSESSED
    for absent in ("severity", "score", "cvss", "probability", "confidence", "exploitability"):
        assert absent not in str(list(dns_path)) and absent not in body
    assert zero_hop["is_zero_hop"] is True and zero_hop["basis"] == "direct_exposure" and zero_hop["steps"] == []


def test_analyst_assertion_reference_hides_who(client, db, admin):
    headers, org, user = admin
    edge = make_asset(db, org, "edge-api.example.com")
    payroll = make_asset(db, org, "payroll-api.example.com", criticality=AssetCriticality.critical)
    http_result(db, org, user, edge, "https", at=_now() - timedelta(hours=2))
    db.flush()
    created = client.post(
        f"/assets/{edge.id}/relationships",
        json={"target_asset_id": str(payroll.id), "relationship_type": "exposes"},
        headers=headers,
    )
    assert created.status_code == 201, created.text

    (path,) = client.get(URL, headers=headers).json()["paths"]

    (step,) = path["steps"]
    assert step["basis"] == "analyst_asserted" and step["relationship_source"] == "manual"
    assert step["analyst_assertion"]["audit_log_id"] and step["analyst_assertion"]["asserted_at"]
    assert str(user.id) not in str(path)  # who asserted it stays in the admin-only audit log


# --- 25. Empty and isolation -----------------------------------------------------------------


def test_empty_organization(client, admin):
    headers, _, _ = admin

    body = client.get(URL, headers=headers).json()

    assert body["paths"] == [] and body["path_count"] == 0 and body["eligible_target_count"] == 0
    assert body["truncated"] is False


def test_another_organizations_paths_and_identities_never_appear(client, register_user, db, admin):
    _, org, user = admin
    graph = _graph(db, org, user, evidence_at=_now() - timedelta(hours=2))
    other_headers = register_user(email="paths-other@example.com", org_name="Other Paths Org")

    resp = client.get(URL, headers=other_headers)

    assert resp.status_code == 200
    body = resp.json()
    assert body["paths"] == [] and body["eligible_target_count"] == 0 and body["entry_point_count"] == 0
    for asset in graph.values():
        assert str(asset.id) not in resp.text
    assert "site.example.com" not in resp.text and str(org.id) not in resp.text


# --- 24. Read-only, no discovery, route ordering -----------------------------------------------


def test_get_is_read_only_and_triggers_nothing(client, db, admin, monkeypatch):
    headers, org, user = admin
    _graph(db, org, user, evidence_at=_now() - timedelta(hours=2))
    from app.services import discovery_service, scan_service

    def refuse(*args, **kwargs):
        raise AssertionError("GET /assets/exposure-paths must not start discovery or scanning")

    monkeypatch.setattr(discovery_service, "execute_run", refuse)
    monkeypatch.setattr(scan_service, "create_scan", refuse, raising=False)

    def counts():
        return [db.query(model).count() for model in (Asset, DiscoveryRun, Scan, Observation, AuditLog)]

    before = counts()
    resp = client.get(URL, headers=headers)

    assert resp.status_code == 200 and counts() == before


def test_static_route_is_not_mistaken_for_an_asset_id(client, db, admin):
    headers, org, user = admin
    graph = _graph(db, org, user, evidence_at=_now() - timedelta(hours=2))

    assert client.get(URL, headers=headers).status_code == 200
    assert client.get(f"/assets/{graph['site'].id}", headers=headers).status_code == 200
    assert client.get(f"/assets/{uuid.uuid4()}", headers=headers).status_code == 404
