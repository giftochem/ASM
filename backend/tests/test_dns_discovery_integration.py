"""API-level integration tests for the "dns" discovery provider — no
network, dns.resolver.Resolver.resolve is monkeypatched exactly like in
test_dns_provider.py. Authorization/RBAC/org-isolation are already
proven generically in test_discovery_runs.py (they're enforced in
discovery_service before any provider is even resolved); the handful
here just confirm the wiring holds for "dns" specifically too, per the
instructions' explicit checklist, without re-deriving Step 9.1's own
coverage.
"""

import dns.resolver


class _FakeRdata:
    def __init__(self, text: str):
        self._text = text

    def to_text(self) -> str:
        return self._text


class _FakeRRset:
    def __init__(self, ttl: int = 300):
        self.ttl = ttl


class _FakeAnswer(list):
    def __init__(self, values: list[str]):
        super().__init__(_FakeRdata(v) for v in values)
        self.rrset = _FakeRRset()


def _install_fake_resolver(monkeypatch, responses: dict[str, list[str] | Exception]):
    def _fake_resolve(self, name, rdtype, *args, **kwargs):
        response = responses.get(rdtype, dns.resolver.NoAnswer())
        if isinstance(response, Exception):
            raise response
        return _FakeAnswer(response)

    monkeypatch.setattr(dns.resolver.Resolver, "resolve", _fake_resolve)


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


def _run_dns_discovery(client, headers, seed_id):
    resp = client.post(
        "/discovery/runs", json={"seed_asset_id": seed_id, "provider_name": "dns"}, headers=headers
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


# --- Core discovery-to-graph behavior ---------------------------------------


def test_dns_discovery_creates_ip_asset_and_relationship(client, register_user, monkeypatch):
    _install_fake_resolver(monkeypatch, {"A": ["93.184.216.34"]})
    headers = register_user()
    seed = _create_and_authorize_asset(client, headers, "dns-a.example.com")

    run = _run_dns_discovery(client, headers, seed["id"])
    assert run["status"] == "completed"
    assert run["error_message"] is None

    results = client.get(f"/discovery/runs/{run['id']}/results", headers=headers).json()
    assert len(results) == 1
    assert results[0]["outcome"] == "created"
    assert results[0]["candidate_value"] == "93.184.216.34"

    ip_asset = client.get(f"/assets/{results[0]['resulting_asset_id']}", headers=headers).json()
    assert ip_asset["asset_type"] == "ip_address"
    assert ip_asset["value"] == "93.184.216.34"
    assert ip_asset["source"] == "discovery"

    relationships = client.get(f"/assets/{seed['id']}/relationships", headers=headers).json()
    assert len(relationships) == 1
    assert relationships[0]["relationship_type"] == "resolves_to"
    assert relationships[0]["source_asset_id"] == seed["id"]
    assert relationships[0]["target_asset_id"] == ip_asset["id"]

    observations = client.get(f"/assets/{seed['id']}/observations", headers=headers).json()
    assert "relationship_created" in [o["change_type"] for o in observations]


def test_txt_records_become_observation_not_asset(client, register_user, monkeypatch):
    _install_fake_resolver(monkeypatch, {"TXT": ['"v=spf1 include:_spf.example.com ~all"']})
    headers = register_user()
    seed = _create_and_authorize_asset(client, headers, "dns-txt.example.com")

    run = _run_dns_discovery(client, headers, seed["id"])

    results = client.get(f"/discovery/runs/{run['id']}/results", headers=headers).json()
    assert len(results) == 1
    assert results[0]["outcome"] == "observed"
    assert results[0]["resulting_asset_id"] == seed["id"]

    all_assets = client.get("/assets", headers=headers).json()
    assert len(all_assets) == 1  # only the seed -- no TXT-derived asset

    observations = client.get(f"/assets/{seed['id']}/observations", headers=headers).json()
    dns_observation = next(o for o in observations if o["change_type"] == "dns_records_observed")
    assert "v=spf1" in dns_observation["current_value"]


def test_out_of_scope_target_rejected_recorded_as_evidence_only(client, register_user, monkeypatch):
    _install_fake_resolver(monkeypatch, {"NS": ["ns1.registrar-dns.com."]})
    headers = register_user()
    seed = _create_and_authorize_asset(client, headers, "dns-ns.example.com")

    run = _run_dns_discovery(client, headers, seed["id"])

    results = client.get(f"/discovery/runs/{run['id']}/results", headers=headers).json()
    assert len(results) == 1
    assert results[0]["outcome"] == "observed"

    all_assets = client.get("/assets", headers=headers).json()
    assert len(all_assets) == 1  # only the seed -- out-of-scope NS target never became an asset

    relationships = client.get(f"/assets/{seed['id']}/relationships", headers=headers).json()
    assert relationships == []


def test_repeated_dns_discovery_refreshes_instead_of_duplicating(client, register_user, monkeypatch):
    _install_fake_resolver(monkeypatch, {"A": ["93.184.216.34"]})
    headers = register_user()
    seed = _create_and_authorize_asset(client, headers, "dns-repeat.example.com")

    first_run = _run_dns_discovery(client, headers, seed["id"])
    second_run = _run_dns_discovery(client, headers, seed["id"])

    first_results = client.get(f"/discovery/runs/{first_run['id']}/results", headers=headers).json()
    second_results = client.get(f"/discovery/runs/{second_run['id']}/results", headers=headers).json()
    assert first_results[0]["outcome"] == "created"
    # Step 9.9.2: nothing meaningful changed about the IP asset itself
    # between the two runs -- see test_discovery_runs.py's identical
    # note for the full reasoning.
    assert second_results[0]["outcome"] == "unchanged"
    assert first_results[0]["resulting_asset_id"] == second_results[0]["resulting_asset_id"]

    all_assets = client.get("/assets", headers=headers).json()
    ip_assets = [a for a in all_assets if a["asset_type"] == "ip_address"]
    assert len(ip_assets) == 1

    relationships = client.get(f"/assets/{seed['id']}/relationships", headers=headers).json()
    assert len(relationships) == 1


def test_one_failed_record_type_does_not_corrupt_the_whole_run(client, register_user, monkeypatch):
    """A record lookup raises unexpectedly; AAAA still resolves. The run
    must still complete with the AAAA candidate present, not fail
    outright or lose the other record types' results.
    """
    _install_fake_resolver(
        monkeypatch,
        {"A": RuntimeError("simulated resolver crash"), "AAAA": ["2606:2800:220:1:248:1893:25c8:1946"]},
    )
    headers = register_user()
    seed = _create_and_authorize_asset(client, headers, "dns-partial-fail.example.com")

    run = _run_dns_discovery(client, headers, seed["id"])
    assert run["status"] == "completed"
    assert run["error_message"] is None

    results = client.get(f"/discovery/runs/{run['id']}/results", headers=headers).json()
    assert len(results) == 1
    assert results[0]["candidate_value"] == "2606:2800:220:1:248:1893:25c8:1946"


# --- Authorization / RBAC / org isolation, confirmed specifically for "dns" -


def test_dns_discovery_requires_authorization(client, register_user):
    headers = register_user()
    unauthorized = client.post(
        "/assets", json={"asset_type": "domain", "value": "dns-unauth.example.com"}, headers=headers
    ).json()

    resp = client.post(
        "/discovery/runs",
        json={"seed_asset_id": unauthorized["id"], "provider_name": "dns"},
        headers=headers,
    )
    assert resp.status_code == 403


def test_viewer_cannot_run_dns_discovery(client, register_user, login_as):
    admin_headers = register_user(email="dns-org-admin@example.com")
    seed = _create_and_authorize_asset(client, admin_headers, "dns-viewer-blocked.example.com")

    viewer_resp = client.post(
        "/users",
        json={
            "email": "dns-viewer@example.com",
            "password": "correct-horse-battery",
            "full_name": "Viewer Person",
            "role": "viewer",
        },
        headers=admin_headers,
    )
    assert viewer_resp.status_code == 201
    viewer_headers = login_as("dns-viewer@example.com", "correct-horse-battery")

    resp = client.post(
        "/discovery/runs",
        json={"seed_asset_id": seed["id"], "provider_name": "dns"},
        headers=viewer_headers,
    )
    assert resp.status_code == 403


def test_dns_discovery_results_are_isolated_between_organizations(client, register_user, monkeypatch):
    _install_fake_resolver(monkeypatch, {"A": ["93.184.216.34"]})
    org_a_headers = register_user(org_name="Org A", email="dns-iso-a@example.com")
    org_b_headers = register_user(org_name="Org B", email="dns-iso-b@example.com")

    seed = _create_and_authorize_asset(client, org_a_headers, "dns-iso.example.com")
    run = _run_dns_discovery(client, org_a_headers, seed["id"])

    assert client.get(f"/discovery/runs/{run['id']}", headers=org_b_headers).status_code == 404
    assert client.get(f"/discovery/runs/{run['id']}/results", headers=org_b_headers).status_code == 404
