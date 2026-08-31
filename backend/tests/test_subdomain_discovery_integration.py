"""API-level integration tests for the "subdomain" discovery provider.
Only the external HTTP call to crt.sh is mocked (at
subdomain_provider's own httpx.get reference) -- provider selection,
authorization, RBAC, org isolation, and scope validation all run
through the real, unmocked discovery pipeline, proving those guarantees
hold in the actual code path, not just in a mock.
"""

import uuid

import app.discovery.subdomain_provider as subdomain_provider_module
from app.core.enums import LifecycleStatus
from app.models.asset import Asset


def _entry(name_value: str) -> dict:
    return {"name_value": name_value}


class _FakeResponse:
    def __init__(self, json_data):
        self._json_data = json_data
        self.status_code = 200

    def raise_for_status(self):
        pass

    def json(self):
        return self._json_data


def _patch_ct_response(monkeypatch, entries: list[dict]):
    def _fake_get(url, params=None, timeout=None):
        return _FakeResponse(entries)

    monkeypatch.setattr(subdomain_provider_module.httpx, "get", _fake_get)


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


def _run_subdomain_discovery(client, headers, seed_id):
    resp = client.post(
        "/discovery/runs", json={"seed_asset_id": seed_id, "provider_name": "subdomain"}, headers=headers
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def test_subdomain_discovery_requires_authorization(client, register_user):
    headers = register_user()
    unauthorized = client.post(
        "/assets", json={"asset_type": "domain", "value": "sub-unauth.example.com"}, headers=headers
    ).json()

    resp = client.post(
        "/discovery/runs",
        json={"seed_asset_id": unauthorized["id"], "provider_name": "subdomain"},
        headers=headers,
    )
    assert resp.status_code == 403


def test_viewer_cannot_run_subdomain_discovery(client, register_user, login_as, monkeypatch):
    _patch_ct_response(monkeypatch, [_entry("api.sub-viewer.example.com")])
    admin_headers = register_user(email="sub-org-admin@example.com")
    seed = _create_and_authorize_asset(client, admin_headers, "sub-viewer.example.com")

    viewer_resp = client.post(
        "/users",
        json={
            "email": "sub-viewer@example.com",
            "password": "correct-horse-battery",
            "full_name": "Viewer Person",
            "role": "viewer",
        },
        headers=admin_headers,
    )
    assert viewer_resp.status_code == 201
    viewer_headers = login_as("sub-viewer@example.com", "correct-horse-battery")

    resp = client.post(
        "/discovery/runs",
        json={"seed_asset_id": seed["id"], "provider_name": "subdomain"},
        headers=viewer_headers,
    )
    assert resp.status_code == 403


def test_subdomain_discovery_results_are_isolated_between_organizations(client, register_user, monkeypatch):
    _patch_ct_response(monkeypatch, [_entry("api.sub-iso.example.com")])
    org_a_headers = register_user(org_name="Org A", email="sub-iso-a@example.com")
    org_b_headers = register_user(org_name="Org B", email="sub-iso-b@example.com")

    seed = _create_and_authorize_asset(client, org_a_headers, "sub-iso.example.com")
    run = _run_subdomain_discovery(client, org_a_headers, seed["id"])

    assert client.get(f"/discovery/runs/{run['id']}", headers=org_b_headers).status_code == 404
    assert client.get(f"/discovery/runs/{run['id']}/results", headers=org_b_headers).status_code == 404


def test_discovered_hostname_becomes_asset_with_correct_relationship_and_observation(
    client, register_user, monkeypatch
):
    _patch_ct_response(monkeypatch, [_entry("api.sub-a.example.com\nwww.sub-a.example.com")])
    headers = register_user()
    seed = _create_and_authorize_asset(client, headers, "sub-a.example.com")

    run = _run_subdomain_discovery(client, headers, seed["id"])
    assert run["status"] == "completed"

    # 2 discovered-hostname results + 1 seed-evidence result (this
    # provider always records what it found for the seed itself, even
    # when there's nothing noteworthy in it -- see record_seed_evidence).
    results = client.get(f"/discovery/runs/{run['id']}/results", headers=headers).json()
    assert len(results) == 3
    hostname_results = [r for r in results if r["candidate_value"] != "sub-a.example.com"]
    assert len(hostname_results) == 2
    assert all(r["outcome"] == "created" for r in hostname_results)

    all_assets = client.get("/assets", headers=headers).json()
    api_asset = next(a for a in all_assets if a["value"] == "api.sub-a.example.com")
    assert api_asset["asset_type"] == "subdomain"
    assert api_asset["source"] == "discovery"
    assert api_asset["status"] == "first_seen"

    # belongs_to, correctly directed: the discovered asset is the
    # relationship's source, the seed is the target.
    relationships = client.get(f"/assets/{seed['id']}/relationships", headers=headers).json()
    api_relationship = next(r for r in relationships if r["source_asset_id"] == api_asset["id"])
    assert api_relationship["target_asset_id"] == seed["id"]
    assert api_relationship["relationship_type"] == "belongs_to"

    api_observations = client.get(f"/assets/{api_asset['id']}/observations", headers=headers).json()
    change_types = [o["change_type"] for o in api_observations]
    assert "asset_created" in change_types
    assert "relationship_created" in change_types


def test_repeated_discovery_refreshes_instead_of_duplicating(client, register_user, monkeypatch):
    _patch_ct_response(monkeypatch, [_entry("api.sub-b.example.com")])
    headers = register_user()
    seed = _create_and_authorize_asset(client, headers, "sub-b.example.com")

    first = _run_subdomain_discovery(client, headers, seed["id"])
    second = _run_subdomain_discovery(client, headers, seed["id"])

    def _hostname_outcome(run_id):
        results = client.get(f"/discovery/runs/{run_id}/results", headers=headers).json()
        return next(r["outcome"] for r in results if r["candidate_value"] == "api.sub-b.example.com")

    first_outcome = _hostname_outcome(first["id"])
    second_outcome = _hostname_outcome(second["id"])
    assert first_outcome == "created"
    # Step 9.9.2: nothing meaningful changed about the hostname asset
    # itself between the two runs -- see test_discovery_runs.py's
    # identical note for the full reasoning.
    assert second_outcome == "unchanged"

    all_assets = client.get("/assets", headers=headers).json()
    matching = [a for a in all_assets if a["value"] == "api.sub-b.example.com"]
    assert len(matching) == 1  # no duplicate

    relationships = client.get(f"/assets/{seed['id']}/relationships", headers=headers).json()
    assert len(relationships) == 1  # relationship refreshed, not duplicated


def test_wildcard_and_external_names_never_become_assets(client, register_user, monkeypatch):
    _patch_ct_response(
        monkeypatch,
        [_entry("*.sub-c.example.com\napi.sub-c.example.com\nvendor.example.net\nsub-c.example.com.evil.com")],
    )
    headers = register_user()
    seed = _create_and_authorize_asset(client, headers, "sub-c.example.com")
    _run_subdomain_discovery(client, headers, seed["id"])

    all_assets = client.get("/assets", headers=headers).json()
    values = {a["value"] for a in all_assets}
    assert "*.sub-c.example.com" not in values
    assert "vendor.example.net" not in values
    assert "sub-c.example.com.evil.com" not in values
    assert "api.sub-c.example.com" in values

    seed_observations = client.get(f"/assets/{seed['id']}/observations", headers=headers).json()
    ct_observation = next(o for o in seed_observations if o["change_type"] == "certificate_transparency_observed")
    assert "vendor.example.net" in ct_observation["current_value"]
    assert "*.sub-c.example.com" in ct_observation["current_value"]


def test_malformed_entry_does_not_corrupt_the_run(client, register_user, monkeypatch):
    _patch_ct_response(monkeypatch, [{"name_value": None}, _entry("api.sub-d.example.com")])
    headers = register_user()
    seed = _create_and_authorize_asset(client, headers, "sub-d.example.com")

    run = _run_subdomain_discovery(client, headers, seed["id"])
    assert run["status"] == "completed"

    results = client.get(f"/discovery/runs/{run['id']}/results", headers=headers).json()
    hostname_results = [r for r in results if r["candidate_value"] != "sub-d.example.com"]
    assert len(hostname_results) == 1
    assert hostname_results[0]["candidate_value"] == "api.sub-d.example.com"


def test_provider_failure_produces_failed_run(client, register_user, monkeypatch):
    def _raise(url, params=None, timeout=None):
        raise ConnectionError("simulated crt.sh outage")

    monkeypatch.setattr(subdomain_provider_module.httpx, "get", _raise)

    headers = register_user()
    seed = _create_and_authorize_asset(client, headers, "sub-e.example.com")
    run = _run_subdomain_discovery(client, headers, seed["id"])

    assert run["status"] == "failed"
    assert run["error_message"] is not None
    results = client.get(f"/discovery/runs/{run['id']}/results", headers=headers).json()
    assert results == []


def test_unicode_hostname_is_safely_rejected_not_mismatched(client, register_user, db, monkeypatch):
    """Exercises the real normalize_candidate pipeline, not just the
    provider: a raw Unicode CT name is classified as in-scope by
    is_hostname_in_scope's pure string comparison (labels align), but
    the existing ASCII-only hostname validation rejects it as an invalid
    value once it reaches normalization -- safe-by-rejection, not
    silently mis-scoped or corrupted.
    """
    _patch_ct_response(monkeypatch, [_entry("café.sub-f.example.com\napi.sub-f.example.com")])
    headers = register_user()
    seed = _create_and_authorize_asset(client, headers, "sub-f.example.com")

    run = _run_subdomain_discovery(client, headers, seed["id"])
    results = client.get(f"/discovery/runs/{run['id']}/results", headers=headers).json()

    outcomes = {r["candidate_value"]: r["outcome"] for r in results}
    assert outcomes["api.sub-f.example.com"] == "created"
    unicode_result = next(r for r in results if "caf" in r["candidate_value"])
    assert unicode_result["outcome"] == "rejected"

    all_assets = client.get("/assets", headers=headers).json()
    assert all("café" not in a["value"] for a in all_assets)


# --- Confirm existing providers are unaffected ----------------------------
# (test_dns_provider.py / test_dns_discovery_integration.py /
# test_certificate_provider.py / test_certificate_discovery_integration.py
# are re-run unmodified as part of full-suite regression -- that's the
# real confirmation those providers still work. This just checks
# registration wasn't accidentally broken, with no network I/O.)


def test_all_seven_providers_still_registered():
    # Updated in Step 9.7 to include "cloud" -- this test's job is only
    # to catch an accidental registration break, not to gate future
    # providers; test_cloud_discovery_integration.py's own copy of this
    # assertion is the authoritative one for the current provider set.
    from app.discovery.registry import all_provider_names

    assert set(all_provider_names()) == {"stub", "dns", "certificate", "subdomain", "http", "network", "cloud"}
