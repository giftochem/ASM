"""API-level integration tests for the "network" discovery provider.
Only the external DNS calls are mocked (at dns.resolver.Resolver.resolve,
the provider's own external-call boundary) -- provider selection,
authorization, RBAC, org isolation, and the Asset/Observation/
DiscoveryResult pipeline all run through the real, unmocked discovery
pipeline.
"""

import threading
import uuid

import dns.resolver
import dns.reversename

from app.core.enums import AssetType, RelationshipType
from app.discovery.base import DiscoveryCandidate
from app.models.asset import Asset
from app.models.discovery_run import DiscoveryRun
from app.models.user import User
from app.services import discovery_normalization_service, discovery_service
from tests.conftest import TestSessionLocal


class _FakeRdata:
    def __init__(self, text: str):
        self._text = text

    def to_text(self) -> str:
        return self._text


class _FakeAnswer(list):
    def __init__(self, values: list[str]):
        super().__init__(_FakeRdata(v) for v in values)


def _ptr_name(ip: str) -> str:
    return str(dns.reversename.from_address(ip))


def _install_fake_resolver(monkeypatch, responses: dict[str, list[str] | Exception]):
    def _fake_resolve(self, name, rdtype, *args, **kwargs):
        key = str(name)
        if key not in responses:
            raise dns.resolver.NXDOMAIN()
        response = responses[key]
        if isinstance(response, Exception):
            raise response
        return _FakeAnswer(response)

    monkeypatch.setattr(dns.resolver.Resolver, "resolve", _fake_resolve)


def _origin_query_name(ip: str) -> str:
    # Team Cymru's IPv4 origin lookup uses the octets in reverse order
    # (independently reimplemented here, not imported from the provider,
    # so this test doesn't just echo the provider's own logic back at
    # itself) -- e.g. "93.184.216.40" -> "40.216.184.93.origin.asn.cymru.com".
    return ".".join(reversed(ip.split("."))) + ".origin.asn.cymru.com"


def _google_responses(ip: str = "8.8.8.8", asn: str = "15169", org: str = "GOOGLE - Google LLC, US") -> dict:
    return {
        _origin_query_name(ip): [f'"{asn} | 8.8.8.0/24 | US | arin | 2023-12-28"'],
        f"AS{asn}.asn.cymru.com": [f'"{asn} | US | arin | 2000-03-30 | {org}"'],
        _ptr_name(ip): ["dns.google."],
    }


def _create_and_authorize_asset(client, headers, value, asset_type="ip_address"):
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


def _run_network_discovery(client, headers, seed_id):
    resp = client.post(
        "/discovery/runs", json={"seed_asset_id": seed_id, "provider_name": "network"}, headers=headers
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def test_network_discovery_requires_authorization(client, register_user):
    headers = register_user()
    unauthorized = client.post(
        "/assets", json={"asset_type": "ip_address", "value": "93.184.216.39"}, headers=headers
    ).json()

    resp = client.post(
        "/discovery/runs",
        json={"seed_asset_id": unauthorized["id"], "provider_name": "network"},
        headers=headers,
    )
    assert resp.status_code == 403


def test_viewer_cannot_run_network_discovery(client, register_user, login_as, monkeypatch):
    _install_fake_resolver(monkeypatch, _google_responses(ip="93.184.216.34"))
    admin_headers = register_user(email="net-org-admin@example.com")
    seed = _create_and_authorize_asset(client, admin_headers, "93.184.216.34")

    viewer_resp = client.post(
        "/users",
        json={
            "email": "net-viewer@example.com",
            "password": "correct-horse-battery",
            "full_name": "Viewer Person",
            "role": "viewer",
        },
        headers=admin_headers,
    )
    assert viewer_resp.status_code == 201
    viewer_headers = login_as("net-viewer@example.com", "correct-horse-battery")

    resp = client.post(
        "/discovery/runs", json={"seed_asset_id": seed["id"], "provider_name": "network"}, headers=viewer_headers
    )
    assert resp.status_code == 403


def test_network_discovery_results_are_isolated_between_organizations(client, register_user, monkeypatch):
    _install_fake_resolver(monkeypatch, _google_responses(ip="93.184.216.35"))
    org_a_headers = register_user(org_name="Org A", email="net-iso-a@example.com")
    org_b_headers = register_user(org_name="Org B", email="net-iso-b@example.com")

    seed = _create_and_authorize_asset(client, org_a_headers, "93.184.216.35")
    run = _run_network_discovery(client, org_a_headers, seed["id"])

    assert client.get(f"/discovery/runs/{run['id']}", headers=org_b_headers).status_code == 404
    assert client.get(f"/discovery/runs/{run['id']}/results", headers=org_b_headers).status_code == 404


def test_valid_ip_seed_creates_asn_asset_and_announced_by_relationship(client, register_user, monkeypatch):
    ip = "93.184.216.40"
    _install_fake_resolver(monkeypatch, _google_responses(ip=ip, asn="64500", org="EXAMPLE-NET, US"))
    headers = register_user()
    seed = _create_and_authorize_asset(client, headers, ip)

    run = _run_network_discovery(client, headers, seed["id"])
    assert run["status"] == "completed"

    all_assets = client.get("/assets", headers=headers).json()
    asn_asset = next(a for a in all_assets if a["asset_type"] == "asn")
    assert asn_asset["value"] == "AS64500"
    assert asn_asset["source"] == "discovery"

    relationships = client.get(f"/assets/{seed['id']}/relationships", headers=headers).json()
    rel = next(r for r in relationships if r["relationship_type"] == "announced_by")
    assert rel["source_asset_id"] == seed["id"]
    assert rel["target_asset_id"] == asn_asset["id"]

    observations = client.get(f"/assets/{seed['id']}/observations", headers=headers).json()
    network_obs = [o for o in observations if o["change_type"] == "network_observed"]
    assert len(network_obs) == 1
    assert '"asn": "AS64500"' in network_obs[0]["current_value"]


def test_no_duplicate_asn_asset_across_two_ip_seeds_with_same_asn(client, register_user, monkeypatch):
    headers = register_user()
    ip_a, ip_b = "93.184.216.41", "93.184.216.42"
    seed_a = _create_and_authorize_asset(client, headers, ip_a)
    seed_b = _create_and_authorize_asset(client, headers, ip_b)

    responses = {}
    responses.update(_google_responses(ip=ip_a, asn="64501", org="SHARED-NET, US"))
    responses.update(_google_responses(ip=ip_b, asn="64501", org="SHARED-NET, US"))

    def _fake_resolve(self, name, rdtype, *args, **kwargs):
        key = str(name)
        if key not in responses:
            raise dns.resolver.NXDOMAIN()
        return _FakeAnswer(responses[key])

    monkeypatch.setattr(dns.resolver.Resolver, "resolve", _fake_resolve)

    _run_network_discovery(client, headers, seed_a["id"])
    _run_network_discovery(client, headers, seed_b["id"])

    all_assets = client.get("/assets", headers=headers).json()
    asn_assets = [a for a in all_assets if a["asset_type"] == "asn" and a["value"] == "AS64501"]
    assert len(asn_assets) == 1  # one shared ASN, not duplicated

    rels_a = client.get(f"/assets/{seed_a['id']}/relationships", headers=headers).json()
    rels_b = client.get(f"/assets/{seed_b['id']}/relationships", headers=headers).json()
    assert rels_a[0]["target_asset_id"] == asn_assets[0]["id"]
    assert rels_b[0]["target_asset_id"] == asn_assets[0]["id"]


def test_repeated_discovery_is_unchanged_when_nothing_changed(client, register_user, monkeypatch):
    ip = "93.184.216.43"
    _install_fake_resolver(monkeypatch, _google_responses(ip=ip, asn="64502"))
    headers = register_user()
    seed = _create_and_authorize_asset(client, headers, ip)

    first = _run_network_discovery(client, headers, seed["id"])
    second = _run_network_discovery(client, headers, seed["id"])

    def _network_outcome(run_id):
        results = client.get(f"/discovery/runs/{run_id}/results", headers=headers).json()
        return next(r["outcome"] for r in results if r["candidate_value"] == ip)

    assert _network_outcome(first["id"]) == "observed"
    assert _network_outcome(second["id"]) == "unchanged"

    observations = client.get(f"/assets/{seed['id']}/observations", headers=headers).json()
    assert len([o for o in observations if o["change_type"] == "network_changed"]) == 0

    all_assets = client.get("/assets", headers=headers).json()
    asn_assets = [a for a in all_assets if a["asset_type"] == "asn"]
    assert len(asn_assets) == 1  # no duplicate ASN asset from the second run either


def test_asn_change_is_detected_and_recorded(client, register_user, monkeypatch):
    ip = "93.184.216.44"
    headers = register_user()
    seed = _create_and_authorize_asset(client, headers, ip)

    _install_fake_resolver(monkeypatch, _google_responses(ip=ip, asn="64503", org="OLD-NET, US"))
    first = _run_network_discovery(client, headers, seed["id"])
    assert first["status"] == "completed"

    _install_fake_resolver(monkeypatch, _google_responses(ip=ip, asn="64504", org="NEW-NET, US"))
    second = _run_network_discovery(client, headers, seed["id"])

    results = client.get(f"/discovery/runs/{second['id']}/results", headers=headers).json()
    network_result = next(r for r in results if r["candidate_value"] == ip)
    assert network_result["outcome"] == "refreshed"

    observations = client.get(f"/assets/{seed['id']}/observations", headers=headers).json()
    changed = [o for o in observations if o["change_type"] == "network_changed"]
    assert len(changed) == 1
    assert '"asn": "AS64503"' in changed[0]["previous_value"]
    assert '"asn": "AS64504"' in changed[0]["current_value"]

    all_assets = client.get("/assets", headers=headers).json()
    asn_assets = {a["value"] for a in all_assets if a["asset_type"] == "asn"}
    assert asn_assets == {"AS64503", "AS64504"}  # both remain as real, distinct assets


def test_ptr_change_is_detected_and_recorded(client, register_user, monkeypatch):
    ip = "93.184.216.45"
    headers = register_user()
    seed = _create_and_authorize_asset(client, headers, ip)

    responses_v1 = _google_responses(ip=ip, asn="64505")
    responses_v1[_ptr_name(ip)] = ["old-host.example.net."]
    _install_fake_resolver(monkeypatch, responses_v1)
    _run_network_discovery(client, headers, seed["id"])

    responses_v2 = _google_responses(ip=ip, asn="64505")
    responses_v2[_ptr_name(ip)] = ["new-host.example.net."]
    _install_fake_resolver(monkeypatch, responses_v2)
    second = _run_network_discovery(client, headers, seed["id"])

    results = client.get(f"/discovery/runs/{second['id']}/results", headers=headers).json()
    network_result = next(r for r in results if r["candidate_value"] == ip)
    assert network_result["outcome"] == "refreshed"
    assert network_result["evidence"]["ptr_hostname"] == "new-host.example.net"


def test_external_ptr_hostname_never_becomes_an_asset(client, register_user, monkeypatch):
    ip = "93.184.216.46"
    responses = _google_responses(ip=ip, asn="64506")
    responses[_ptr_name(ip)] = ["unrelated-provider.example.net."]
    _install_fake_resolver(monkeypatch, responses)
    headers = register_user()
    seed = _create_and_authorize_asset(client, headers, ip)

    _run_network_discovery(client, headers, seed["id"])

    all_assets = client.get("/assets", headers=headers).json()
    values = {a["value"] for a in all_assets}
    assert "unrelated-provider.example.net" not in values
    # Only the seed IP and its ASN exist.
    assert len(all_assets) == 2


def test_provider_failure_does_not_corrupt_the_run(client, register_user, monkeypatch):
    def _raise(self, name, rdtype, *args, **kwargs):
        raise ConnectionError("simulated resolver outage")

    monkeypatch.setattr(dns.resolver.Resolver, "resolve", _raise)
    headers = register_user()
    seed = _create_and_authorize_asset(client, headers, "93.184.216.47")

    run = _run_network_discovery(client, headers, seed["id"])

    assert run["status"] == "completed"  # a total lookup failure is a normal outcome, not a crash
    results = client.get(f"/discovery/runs/{run['id']}/results", headers=headers).json()
    assert results[0]["outcome"] == "failed"


def test_ip_discovered_by_dns_provider_is_enriched_by_network_provider_on_the_same_asset(
    client, register_user, monkeypatch
):
    ip = "93.184.216.48"

    def _fake_dns_provider_resolve(self, name, rdtype, *args, **kwargs):
        if rdtype == "A":
            return _FakeAnswer([ip])
        raise dns.resolver.NoAnswer()

    monkeypatch.setattr(dns.resolver.Resolver, "resolve", _fake_dns_provider_resolve)

    headers = register_user()
    domain_seed = _create_and_authorize_asset(client, headers, "dns-then-network.example.com", asset_type="domain")
    dns_run = client.post(
        "/discovery/runs", json={"seed_asset_id": domain_seed["id"], "provider_name": "dns"}, headers=headers
    ).json()
    assert dns_run["status"] == "completed"

    all_assets = client.get("/assets", headers=headers).json()
    ip_asset = next(a for a in all_assets if a["value"] == ip)
    assert ip_asset["authorization_confirmed"] is False  # discovered, not yet authorized

    confirm = client.post(
        f"/assets/{ip_asset['id']}/confirm-authorization", json={"authorization_confirmed": True}, headers=headers
    )
    assert confirm.status_code == 200

    _install_fake_resolver(monkeypatch, _google_responses(ip=ip, asn="64507"))
    network_run = _run_network_discovery(client, headers, ip_asset["id"])
    assert network_run["status"] == "completed"

    all_assets_after = client.get("/assets", headers=headers).json()
    matching_ip_assets = [a for a in all_assets_after if a["value"] == ip]
    assert len(matching_ip_assets) == 1  # same asset, not duplicated
    assert matching_ip_assets[0]["id"] == ip_asset["id"]


def test_all_seven_providers_still_registered():
    # Updated in Step 9.7 to include "cloud" -- this test's job is only
    # to catch an accidental registration break, not to gate future
    # providers; test_cloud_discovery_integration.py's own copy of this
    # assertion is the authoritative one for the current provider set.
    from app.discovery.registry import all_provider_names

    assert set(all_provider_names()) == {"stub", "dns", "certificate", "subdomain", "http", "network", "cloud"}


def test_concurrent_asn_candidate_normalization_does_not_create_duplicate_asn_asset(client, register_user, db):
    headers = register_user(email="net-race-admin@example.com")
    seed_resp = _create_and_authorize_asset(client, headers, "93.184.216.49")
    seed_id = uuid.UUID(seed_resp["id"])

    admin_user = db.query(User).filter(User.email == "net-race-admin@example.com").first()
    run = discovery_service.create_run(db, db.get(Asset, seed_id), "network", admin_user)
    db.commit()
    run_id = run.id

    candidate = DiscoveryCandidate(
        asset_type=AssetType.asn,
        value="AS64999",
        relationship_type=RelationshipType.announced_by,
        confidence=0.9,
    )

    barrier = threading.Barrier(2)
    results = {}
    lock = threading.Lock()

    def _do_normalize(name: str) -> None:
        session = TestSessionLocal()
        try:
            seed_asset = session.get(Asset, seed_id)
            run_obj = session.get(DiscoveryRun, run_id)
            barrier.wait(timeout=5)
            try:
                discovery_normalization_service.normalize_candidate(session, run_obj, seed_asset, candidate)
                session.commit()
                outcome = "ok"
            except Exception as exc:  # pragma: no cover - only hit on an actual regression
                session.rollback()
                outcome = f"error:{exc}"
            with lock:
                results[name] = outcome
        finally:
            session.close()

    t1 = threading.Thread(target=_do_normalize, args=("t1",))
    t2 = threading.Thread(target=_do_normalize, args=("t2",))
    t1.start()
    t2.start()
    t1.join(timeout=10)
    t2.join(timeout=10)

    assert results == {"t1": "ok", "t2": "ok"}

    matching_asn_assets = db.query(Asset).filter(Asset.value == "AS64999", Asset.asset_type == AssetType.asn).all()
    assert len(matching_asn_assets) == 1
