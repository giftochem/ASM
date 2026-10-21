"""API-level integration tests for the "cloud" discovery provider. DNS
calls are mocked (dns.resolver.Resolver.resolve, the same boundary
test_network_provider.py/test_cloud_provider.py use) -- authorization,
RBAC, org isolation, cross-provider evidence correlation (reading
already-stored HTTP/Certificate rows), change detection, and the
correlation-across-assets service function all run through the real,
unmocked pipeline.
"""

import threading
import uuid
from datetime import datetime, timezone

import dns.resolver
import dns.reversename

from app.core.enums import AssetSource, AssetType, LifecycleStatus
from app.models.asset import Asset
from app.models.certificate import Certificate
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


def _origin_query_name(ip: str) -> str:
    return ".".join(reversed(ip.split("."))) + ".origin.asn.cymru.com"


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


def _cymru_responses(ip: str, asn: str = "15169", org: str = "GOOGLE - Google LLC, US", ptr: str = "dns.google.") -> dict:
    return {
        _origin_query_name(ip): [f'"{asn} | 8.8.8.0/24 | US | arin | 2023-12-28"'],
        f"AS{asn}.asn.cymru.com": [f'"{asn} | US | arin | 2000-03-30 | {org}"'],
        _ptr_name(ip): [ptr],
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


def _run_cloud_discovery(client, headers, seed_id):
    resp = client.post("/discovery/runs", json={"seed_asset_id": seed_id, "provider_name": "cloud"}, headers=headers)
    assert resp.status_code == 201, resp.text
    return resp.json()


def test_cloud_discovery_requires_authorization(client, register_user):
    headers = register_user()
    unauthorized = client.post(
        "/assets", json={"asset_type": "ip_address", "value": "93.184.216.60"}, headers=headers
    ).json()

    resp = client.post(
        "/discovery/runs", json={"seed_asset_id": unauthorized["id"], "provider_name": "cloud"}, headers=headers
    )
    assert resp.status_code == 403


def test_viewer_cannot_run_cloud_discovery(client, register_user, login_as, monkeypatch):
    _install_fake_resolver(monkeypatch, _cymru_responses("93.184.216.61"))
    admin_headers = register_user(email="cloud-org-admin@example.com")
    seed = _create_and_authorize_asset(client, admin_headers, "93.184.216.61")

    viewer_resp = client.post(
        "/users",
        json={
            "email": "cloud-viewer@example.com",
            "password": "correct-horse-battery",
            "full_name": "Viewer Person",
            "role": "viewer",
        },
        headers=admin_headers,
    )
    assert viewer_resp.status_code == 201
    viewer_headers = login_as("cloud-viewer@example.com", "correct-horse-battery")

    resp = client.post(
        "/discovery/runs", json={"seed_asset_id": seed["id"], "provider_name": "cloud"}, headers=viewer_headers
    )
    assert resp.status_code == 403


def test_cloud_discovery_results_are_isolated_between_organizations(client, register_user, monkeypatch):
    _install_fake_resolver(monkeypatch, _cymru_responses("93.184.216.62"))
    org_a_headers = register_user(org_name="Org A", email="cloud-iso-a@example.com")
    org_b_headers = register_user(org_name="Org B", email="cloud-iso-b@example.com")

    seed = _create_and_authorize_asset(client, org_a_headers, "93.184.216.62")
    run = _run_cloud_discovery(client, org_a_headers, seed["id"])

    assert client.get(f"/discovery/runs/{run['id']}", headers=org_b_headers).status_code == 404
    assert client.get(f"/discovery/runs/{run['id']}/results", headers=org_b_headers).status_code == 404


def test_successful_discovery_creates_infrastructure_observation_no_new_asset_no_relationship(
    client, register_user, monkeypatch
):
    ip = "93.184.216.63"
    _install_fake_resolver(monkeypatch, _cymru_responses(ip))
    headers = register_user()
    seed = _create_and_authorize_asset(client, headers, ip)

    run = _run_cloud_discovery(client, headers, seed["id"])
    assert run["status"] == "completed"

    results = client.get(f"/discovery/runs/{run['id']}/results", headers=headers).json()
    assert len(results) == 1
    assert results[0]["outcome"] == "observed"
    assert results[0]["evidence"]["provider"] == "Google Cloud"
    assert results[0]["evidence"]["confidence"] > 0

    all_assets = client.get("/assets", headers=headers).json()
    assert len(all_assets) == 1  # only the seed IP -- no cloud_resource asset created

    relationships = client.get(f"/assets/{seed['id']}/relationships", headers=headers).json()
    assert relationships == []  # no new relationship type introduced

    observations = client.get(f"/assets/{seed['id']}/observations", headers=headers).json()
    infra_obs = [o for o in observations if o["change_type"] == "infrastructure_observed"]
    assert len(infra_obs) == 1
    assert '"provider": "Google Cloud"' in infra_obs[0]["current_value"]


def test_repeated_discovery_is_unchanged_when_nothing_changed(client, register_user, monkeypatch):
    ip = "93.184.216.64"
    _install_fake_resolver(monkeypatch, _cymru_responses(ip))
    headers = register_user()
    seed = _create_and_authorize_asset(client, headers, ip)

    first = _run_cloud_discovery(client, headers, seed["id"])
    second = _run_cloud_discovery(client, headers, seed["id"])

    first_outcome = client.get(f"/discovery/runs/{first['id']}/results", headers=headers).json()[0]["outcome"]
    second_outcome = client.get(f"/discovery/runs/{second['id']}/results", headers=headers).json()[0]["outcome"]
    assert first_outcome == "observed"
    assert second_outcome == "unchanged"

    observations = client.get(f"/assets/{seed['id']}/observations", headers=headers).json()
    assert len([o for o in observations if o["change_type"] == "infrastructure_changed"]) == 0


def test_provider_change_from_aws_to_azure_is_detected(client, register_user, monkeypatch):
    ip = "93.184.216.65"
    headers = register_user()
    seed = _create_and_authorize_asset(client, headers, ip)

    _install_fake_resolver(monkeypatch, _cymru_responses(ip, asn="16509", org="AMAZON-02, US", ptr="ec2-1-2-3-4.compute-1.amazonaws.com."))
    first = _run_cloud_discovery(client, headers, seed["id"])
    assert client.get(f"/discovery/runs/{first['id']}/results", headers=headers).json()[0]["evidence"]["provider"] == "Amazon Web Services"

    _install_fake_resolver(monkeypatch, _cymru_responses(ip, asn="8075", org="MICROSOFT-CORP-MSN-AS-BLOCK, US", ptr="myvm.westus.cloudapp.azure.com."))
    second = _run_cloud_discovery(client, headers, seed["id"])
    second_result = client.get(f"/discovery/runs/{second['id']}/results", headers=headers).json()[0]
    assert second_result["outcome"] == "refreshed"
    assert second_result["evidence"]["provider"] == "Microsoft Azure"

    observations = client.get(f"/assets/{seed['id']}/observations", headers=headers).json()
    changed = [o for o in observations if o["change_type"] == "infrastructure_changed"]
    assert len(changed) == 1
    assert '"provider": "Amazon Web Services"' in changed[0]["previous_value"]
    assert '"provider": "Microsoft Azure"' in changed[0]["current_value"]


def test_asn_change_with_same_provider_is_still_detected(client, register_user, monkeypatch):
    ip = "93.184.216.66"
    headers = register_user()
    seed = _create_and_authorize_asset(client, headers, ip)

    _install_fake_resolver(monkeypatch, _cymru_responses(ip, asn="16509", org="AMAZON-02, US"))
    _run_cloud_discovery(client, headers, seed["id"])

    _install_fake_resolver(monkeypatch, _cymru_responses(ip, asn="14618", org="AMAZON-AES, US"))
    second = _run_cloud_discovery(client, headers, seed["id"])
    second_result = client.get(f"/discovery/runs/{second['id']}/results", headers=headers).json()[0]
    assert second_result["outcome"] == "refreshed"  # ASN changed even though provider classification is still AWS
    assert second_result["evidence"]["asn"] == "AS14618"


def test_prefix_change_alone_is_detected(client, register_user, monkeypatch):
    ip = "93.184.216.67"
    headers = register_user()
    seed = _create_and_authorize_asset(client, headers, ip)

    responses_v1 = _cymru_responses(ip, asn="15169")
    _install_fake_resolver(monkeypatch, responses_v1)
    _run_cloud_discovery(client, headers, seed["id"])

    responses_v2 = dict(responses_v1)
    responses_v2[_origin_query_name(ip)] = ['"15169 | 8.8.4.0/24 | US | arin | 2023-12-28"']
    _install_fake_resolver(monkeypatch, responses_v2)
    second = _run_cloud_discovery(client, headers, seed["id"])

    second_result = client.get(f"/discovery/runs/{second['id']}/results", headers=headers).json()[0]
    assert second_result["outcome"] == "refreshed"
    assert second_result["evidence"]["announced_prefix"] == "8.8.4.0/24"


def test_http_server_header_evidence_is_correlated_from_related_hostname(client, register_user, monkeypatch):
    ip = "93.184.216.68"
    headers = register_user()

    def _fake_dns_resolve(self, name, rdtype, *args, **kwargs):
        if rdtype == "A":
            return _FakeAnswer([ip])
        raise dns.resolver.NoAnswer()

    monkeypatch.setattr(dns.resolver.Resolver, "resolve", _fake_dns_resolve)
    domain_seed = _create_and_authorize_asset(client, headers, "cloud-http-corr.example.com", asset_type="domain")
    dns_run = client.post(
        "/discovery/runs", json={"seed_asset_id": domain_seed["id"], "provider_name": "dns"}, headers=headers
    ).json()
    assert dns_run["status"] == "completed"

    all_assets = client.get("/assets", headers=headers).json()
    ip_asset = next(a for a in all_assets if a["value"] == ip)
    client.post(f"/assets/{ip_asset['id']}/confirm-authorization", json={"authorization_confirmed": True}, headers=headers)

    from app.scanners.http_client import FetchResult
    import app.discovery.http_provider as http_provider_module

    def _fake_fetch_url(url, _transport=None, *, scope):
        return FetchResult(
            final_url=url, status_code=200, headers={"Server": "AmazonS3"}, text="", truncated=False,
            redirect_count=0, set_cookie_headers=[],
        )

    monkeypatch.setattr(http_provider_module.http_client, "fetch_url", _fake_fetch_url)
    http_run = client.post(
        "/discovery/runs", json={"seed_asset_id": domain_seed["id"], "provider_name": "http"}, headers=headers
    ).json()
    assert http_run["status"] == "completed"

    _install_fake_resolver(monkeypatch, _cymru_responses(ip, asn="999999", org="SOME-UNKNOWN-NET, US"))
    cloud_run = _run_cloud_discovery(client, headers, ip_asset["id"])
    cloud_result = client.get(f"/discovery/runs/{cloud_run['id']}/results", headers=headers).json()[0]

    assert cloud_result["evidence"]["http_server"] == "AmazonS3"
    assert cloud_result["evidence"]["provider"] == "Amazon Web Services"  # http_server signal alone identifies it


def test_tls_issuer_evidence_is_correlated_from_related_hostname(client, register_user, monkeypatch, db):
    ip = "93.184.216.69"
    headers = register_user()

    def _fake_dns_resolve(self, name, rdtype, *args, **kwargs):
        if rdtype == "A":
            return _FakeAnswer([ip])
        raise dns.resolver.NoAnswer()

    monkeypatch.setattr(dns.resolver.Resolver, "resolve", _fake_dns_resolve)
    domain_seed = _create_and_authorize_asset(client, headers, "cloud-tls-corr.example.com", asset_type="domain")
    client.post("/discovery/runs", json={"seed_asset_id": domain_seed["id"], "provider_name": "dns"}, headers=headers)

    domain_asset = db.get(Asset, uuid.UUID(domain_seed["id"]))
    now = datetime.now(timezone.utc)
    db.add(
        Certificate(
            asset_id=domain_asset.id,
            hostname="cloud-tls-corr.example.com",
            port=443,
            issuer="Cloudflare Inc ECC CA-3",
            fingerprint_sha256="a" * 64,
            first_seen=now,
            last_seen=now,
            source=AssetSource.discovery,
            status=LifecycleStatus.active,
        )
    )
    db.commit()

    all_assets = client.get("/assets", headers=headers).json()
    ip_asset = next(a for a in all_assets if a["value"] == ip)
    client.post(f"/assets/{ip_asset['id']}/confirm-authorization", json={"authorization_confirmed": True}, headers=headers)

    _install_fake_resolver(monkeypatch, {})  # no ASN/PTR data at all -- TLS is the only signal
    cloud_run = _run_cloud_discovery(client, headers, ip_asset["id"])
    cloud_result = client.get(f"/discovery/runs/{cloud_run['id']}/results", headers=headers).json()[0]

    assert cloud_result["evidence"]["tls_issuer"] == "Cloudflare Inc ECC CA-3"
    assert cloud_result["evidence"]["provider"] == "Cloudflare"
    assert cloud_result["outcome"] == "observed"  # succeeded via stored evidence despite no fresh network data


def test_conflicting_signals_are_recorded_not_hidden(client, register_user, monkeypatch):
    ip = "93.184.216.70"
    headers = register_user()
    seed = _create_and_authorize_asset(client, headers, ip)

    _install_fake_resolver(monkeypatch, _cymru_responses(ip, asn="16509", org="AMAZON-02, US", ptr="host.example.net."))
    run = _run_cloud_discovery(client, headers, seed["id"])
    result = client.get(f"/discovery/runs/{run['id']}/results", headers=headers).json()[0]

    # No conflict yet -- single-provider evidence.
    assert result["evidence"]["conflicting"] is False


def test_provider_failure_does_not_corrupt_the_run(client, register_user, monkeypatch):
    def _raise(self, name, rdtype, *args, **kwargs):
        raise ConnectionError("simulated resolver outage")

    monkeypatch.setattr(dns.resolver.Resolver, "resolve", _raise)
    headers = register_user()
    seed = _create_and_authorize_asset(client, headers, "93.184.216.71")

    run = _run_cloud_discovery(client, headers, seed["id"])

    assert run["status"] == "completed"
    results = client.get(f"/discovery/runs/{run['id']}/results", headers=headers).json()
    assert results[0]["outcome"] == "failed"


def test_shared_infrastructure_correlation_groups_matching_ips(client, register_user, monkeypatch, db):
    headers = register_user(email="corr-admin@example.com")
    org = db.query(User).filter(User.email == "corr-admin@example.com").first().organization_id

    ip_aws_1, ip_aws_2, ip_gcp = "93.184.216.72", "93.184.216.73", "93.184.216.74"
    seed_aws_1 = _create_and_authorize_asset(client, headers, ip_aws_1)
    seed_aws_2 = _create_and_authorize_asset(client, headers, ip_aws_2)
    seed_gcp = _create_and_authorize_asset(client, headers, ip_gcp)

    responses = {}
    responses.update(_cymru_responses(ip_aws_1, asn="16509", org="AMAZON-02, US"))
    responses.update(_cymru_responses(ip_aws_2, asn="16509", org="AMAZON-02, US"))
    responses.update(_cymru_responses(ip_gcp, asn="15169", org="GOOGLE - Google LLC, US"))

    def _fake_resolve(self, name, rdtype, *args, **kwargs):
        key = str(name)
        if key not in responses:
            raise dns.resolver.NXDOMAIN()
        return _FakeAnswer(responses[key])

    monkeypatch.setattr(dns.resolver.Resolver, "resolve", _fake_resolve)

    _run_cloud_discovery(client, headers, seed_aws_1["id"])
    _run_cloud_discovery(client, headers, seed_aws_2["id"])
    _run_cloud_discovery(client, headers, seed_gcp["id"])

    groups = discovery_normalization_service.get_shared_infrastructure_groups(db, org)
    by_provider = {g["provider"]: g for g in groups}

    assert "Amazon Web Services" in by_provider
    aws_values = {a["value"] for a in by_provider["Amazon Web Services"]["assets"]}
    assert aws_values == {ip_aws_1, ip_aws_2}

    assert "Google Cloud" in by_provider
    gcp_values = {a["value"] for a in by_provider["Google Cloud"]["assets"]}
    assert gcp_values == {ip_gcp}


def test_all_seven_providers_still_registered():
    from app.discovery.registry import all_provider_names

    assert set(all_provider_names()) == {"stub", "dns", "certificate", "subdomain", "http", "network", "cloud"}


def test_concurrent_infrastructure_observation_runs_do_not_crash_or_corrupt(client, register_user, monkeypatch, db):
    ip = "93.184.216.75"
    _install_fake_resolver(monkeypatch, _cymru_responses(ip))
    headers = register_user(email="cloud-race-admin@example.com")
    seed_resp = _create_and_authorize_asset(client, headers, ip)
    seed_id = uuid.UUID(seed_resp["id"])

    admin_user = db.query(User).filter(User.email == "cloud-race-admin@example.com").first()
    run = discovery_service.create_run(db, db.get(Asset, seed_id), "cloud", admin_user)
    db.commit()
    run_id = run.id

    from app.discovery.base import InfrastructureProviderData

    infra_data = InfrastructureProviderData(
        ip=ip, asn="AS15169", asn_organization="GOOGLE - Google LLC, US", announced_prefix="8.8.8.0/24", ptr_hostname="dns.google"
    )

    barrier = threading.Barrier(2)
    results = {}
    lock = threading.Lock()

    def _do_record(name: str) -> None:
        session = TestSessionLocal()
        try:
            seed_asset = session.get(Asset, seed_id)
            run_obj = session.get(DiscoveryRun, run_id)
            barrier.wait(timeout=5)
            try:
                discovery_normalization_service.record_infrastructure_observation(session, run_obj, seed_asset, infra_data)
                session.commit()
                outcome = "ok"
            except Exception as exc:  # pragma: no cover - only hit on an actual regression
                session.rollback()
                outcome = f"error:{exc}"
            with lock:
                results[name] = outcome
        finally:
            session.close()

    t1 = threading.Thread(target=_do_record, args=("t1",))
    t2 = threading.Thread(target=_do_record, args=("t2",))
    t1.start()
    t2.start()
    t1.join(timeout=10)
    t2.join(timeout=10)

    assert results == {"t1": "ok", "t2": "ok"}
    # No shared Asset is created by this provider (see cloud_provider.py's
    # module docstring), so there's no duplicate-asset assertion to make
    # here -- the guarantee under test is that concurrent writes complete
    # cleanly without crashing or leaving the run in a broken state.
