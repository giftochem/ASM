"""API-level integration tests for the "http" discovery provider. Only
the external network call is mocked (at http_provider's own
http_client.fetch_url reference) -- provider selection, authorization,
RBAC, org isolation, and the Observation/DiscoveryResult pipeline all
run through the real, unmocked discovery pipeline.
"""

import app.discovery.http_provider as http_provider_module
from app.scanners.http_client import FetchResult


def _result(**overrides) -> FetchResult:
    defaults = dict(
        final_url="https://http-int.example.com/",
        status_code=200,
        headers={"Server": "nginx"},
        text="<title>Example</title>",
        truncated=False,
        redirect_count=0,
        set_cookie_headers=[],
    )
    defaults.update(overrides)
    return FetchResult(**defaults)


def _patch_fetch(monkeypatch, mapping: dict):
    def _fake(url, _transport=None):
        return mapping[url]

    monkeypatch.setattr(http_provider_module.http_client, "fetch_url", _fake)


def _default_responses(host: str, **https_overrides) -> dict:
    https_url = f"https://{host}/"
    http_url = f"http://{host}/"
    https_defaults = {"final_url": https_url}
    https_defaults.update(https_overrides)
    return {
        https_url: _result(**https_defaults),
        http_url: _result(final_url=http_url, headers={}, text=""),
    }


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


def _run_http_discovery(client, headers, seed_id):
    resp = client.post("/discovery/runs", json={"seed_asset_id": seed_id, "provider_name": "http"}, headers=headers)
    assert resp.status_code == 201, resp.text
    return resp.json()


def test_http_discovery_requires_authorization(client, register_user):
    headers = register_user()
    unauthorized = client.post(
        "/assets", json={"asset_type": "domain", "value": "http-unauth.example.com"}, headers=headers
    ).json()

    resp = client.post(
        "/discovery/runs", json={"seed_asset_id": unauthorized["id"], "provider_name": "http"}, headers=headers
    )
    assert resp.status_code == 403


def test_viewer_cannot_run_http_discovery(client, register_user, login_as, monkeypatch):
    _patch_fetch(monkeypatch, _default_responses("http-viewer.example.com"))
    admin_headers = register_user(email="http-org-admin@example.com")
    seed = _create_and_authorize_asset(client, admin_headers, "http-viewer.example.com")

    viewer_resp = client.post(
        "/users",
        json={
            "email": "http-viewer@example.com",
            "password": "correct-horse-battery",
            "full_name": "Viewer Person",
            "role": "viewer",
        },
        headers=admin_headers,
    )
    assert viewer_resp.status_code == 201
    viewer_headers = login_as("http-viewer@example.com", "correct-horse-battery")

    resp = client.post(
        "/discovery/runs", json={"seed_asset_id": seed["id"], "provider_name": "http"}, headers=viewer_headers
    )
    assert resp.status_code == 403


def test_http_discovery_results_are_isolated_between_organizations(client, register_user, monkeypatch):
    _patch_fetch(monkeypatch, _default_responses("http-iso.example.com"))
    org_a_headers = register_user(org_name="Org A", email="http-iso-a@example.com")
    org_b_headers = register_user(org_name="Org B", email="http-iso-b@example.com")

    seed = _create_and_authorize_asset(client, org_a_headers, "http-iso.example.com")
    run = _run_http_discovery(client, org_a_headers, seed["id"])

    assert client.get(f"/discovery/runs/{run['id']}", headers=org_b_headers).status_code == 404
    assert client.get(f"/discovery/runs/{run['id']}/results", headers=org_b_headers).status_code == 404


def test_domain_seed_produces_two_observations_no_new_asset_no_relationship(client, register_user, monkeypatch):
    _patch_fetch(monkeypatch, _default_responses("http-a.example.com"))
    headers = register_user()
    seed = _create_and_authorize_asset(client, headers, "http-a.example.com")

    run = _run_http_discovery(client, headers, seed["id"])
    assert run["status"] == "completed"

    results = client.get(f"/discovery/runs/{run['id']}/results", headers=headers).json()
    assert len(results) == 2
    assert all(r["outcome"] == "observed" for r in results)
    assert {r["resulting_asset_id"] for r in results} == {seed["id"]}

    # No new Asset was created -- the hostname stays the one Asset.
    all_assets = client.get("/assets", headers=headers).json()
    assert len(all_assets) == 1
    assert all_assets[0]["id"] == seed["id"]

    # No relationship was created -- HTTP characteristics are evidence,
    # not graph nodes.
    relationships = client.get(f"/assets/{seed['id']}/relationships", headers=headers).json()
    assert relationships == []

    observations = client.get(f"/assets/{seed['id']}/observations", headers=headers).json()
    http_observations = [o for o in observations if o["change_type"] == "http_observed"]
    assert len(http_observations) == 2
    field_names = {o["field_name"] for o in http_observations}
    assert field_names == {"http:https", "http:http"}


def test_repeated_discovery_is_unchanged_when_nothing_changed(client, register_user, monkeypatch):
    _patch_fetch(monkeypatch, _default_responses("http-b.example.com"))
    headers = register_user()
    seed = _create_and_authorize_asset(client, headers, "http-b.example.com")

    first = _run_http_discovery(client, headers, seed["id"])
    second = _run_http_discovery(client, headers, seed["id"])

    first_outcomes = {r["outcome"] for r in client.get(f"/discovery/runs/{first['id']}/results", headers=headers).json()}
    second_outcomes = {r["outcome"] for r in client.get(f"/discovery/runs/{second['id']}/results", headers=headers).json()}
    assert first_outcomes == {"observed"}
    assert second_outcomes == {"unchanged"}

    observations = client.get(f"/assets/{seed['id']}/observations", headers=headers).json()
    http_changed = [o for o in observations if o["change_type"] == "http_changed"]
    assert http_changed == []  # no noise written for an identical re-observation


def test_repeated_discovery_marks_refreshed_when_status_changes(client, register_user, monkeypatch):
    host = "http-c.example.com"
    headers = register_user()
    seed = _create_and_authorize_asset(client, headers, host)

    _patch_fetch(monkeypatch, _default_responses(host, status_code=200))
    first = _run_http_discovery(client, headers, seed["id"])
    assert {r["outcome"] for r in client.get(f"/discovery/runs/{first['id']}/results", headers=headers).json()} == {"observed"}

    _patch_fetch(monkeypatch, _default_responses(host, status_code=503))
    second = _run_http_discovery(client, headers, seed["id"])
    second_results = client.get(f"/discovery/runs/{second['id']}/results", headers=headers).json()
    https_result = next(r for r in second_results if r["candidate_value"] == f"{host}:https")
    assert https_result["outcome"] == "refreshed"

    observations = client.get(f"/assets/{seed['id']}/observations", headers=headers).json()
    changed = [o for o in observations if o["change_type"] == "http_changed" and o["field_name"] == "http:https"]
    assert len(changed) == 1
    assert '"status_code": 503' in changed[0]["current_value"]


def test_one_scheme_failure_does_not_corrupt_the_run(client, register_user, monkeypatch):
    host = "http-d.example.com"
    headers = register_user()
    seed = _create_and_authorize_asset(client, headers, host)

    from app.scanners.http_client import FetchError

    _patch_fetch(
        monkeypatch,
        {
            f"https://{host}/": FetchError("simulated TLS failure"),
            f"http://{host}/": _result(final_url=f"http://{host}/", status_code=200),
        },
    )

    run = _run_http_discovery(client, headers, seed["id"])
    assert run["status"] == "completed"

    results = client.get(f"/discovery/runs/{run['id']}/results", headers=headers).json()
    outcomes = {r["candidate_value"]: r["outcome"] for r in results}
    assert outcomes[f"{host}:https"] == "failed"
    assert outcomes[f"{host}:http"] == "observed"


def test_url_type_seed_produces_exactly_one_result(client, register_user, monkeypatch):
    url_value = "https://http-e.example.com/status"
    headers = register_user()
    seed = _create_and_authorize_asset(client, headers, url_value, asset_type="url")

    _patch_fetch(monkeypatch, {url_value: _result(final_url=url_value, status_code=200)})

    run = _run_http_discovery(client, headers, seed["id"])
    assert run["status"] == "completed"

    results = client.get(f"/discovery/runs/{run['id']}/results", headers=headers).json()
    assert len(results) == 1
    assert results[0]["candidate_value"] == f"{url_value}:https"


def test_all_seven_providers_still_registered():
    # Updated in Step 9.7 to include "cloud" -- this test's job is only
    # to catch an accidental registration break, not to gate future
    # providers; test_cloud_discovery_integration.py's own copy of this
    # assertion is the authoritative one for the current provider set.
    from app.discovery.registry import all_provider_names

    assert set(all_provider_names()) == {"stub", "dns", "certificate", "subdomain", "http", "network", "cloud"}
