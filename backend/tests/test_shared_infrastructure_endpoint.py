"""Tests for GET /assets/shared-infrastructure -- a thin wrapper over
the already-existing, already-exhaustively-tested Step 9.7
discovery_normalization_service.get_shared_infrastructure_groups. These
tests prove the route/auth/org-scoping wiring, not the underlying
classification/grouping logic (see test_cloud_discovery_integration.py
for that).
"""

import dns.resolver
import dns.reversename


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


def _install_fake_resolver(monkeypatch, responses: dict):
    def _fake_resolve(self, name, rdtype, *args, **kwargs):
        key = str(name)
        if key not in responses:
            raise dns.resolver.NXDOMAIN()
        return _FakeAnswer(responses[key])

    monkeypatch.setattr(dns.resolver.Resolver, "resolve", _fake_resolve)


def _cymru_responses(ip: str, asn: str = "15169", org: str = "GOOGLE - Google LLC, US") -> dict:
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


def test_route_returns_empty_list_for_organization_with_no_classified_infrastructure(client, register_user):
    headers = register_user()

    resp = client.get("/assets/shared-infrastructure", headers=headers)
    assert resp.status_code == 200
    assert resp.json() == []


def test_route_authentication_required(client):
    resp = client.get("/assets/shared-infrastructure")
    assert resp.status_code == 401


def test_route_returns_correctly_scoped_grouping(client, register_user, monkeypatch):
    ip = "93.184.216.95"
    _install_fake_resolver(monkeypatch, _cymru_responses(ip))
    headers = register_user()
    seed = _create_and_authorize_asset(client, headers, ip)

    run = client.post("/discovery/runs", json={"seed_asset_id": seed["id"], "provider_name": "cloud"}, headers=headers).json()
    assert run["status"] == "completed"

    resp = client.get("/assets/shared-infrastructure", headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert len(body) == 1
    assert body[0]["provider"] == "Google Cloud"
    assert body[0]["asn"] == "AS15169"
    assert [a["value"] for a in body[0]["assets"]] == [ip]


def test_route_organization_isolation(client, register_user, monkeypatch):
    ip_a, ip_b = "93.184.216.96", "93.184.216.97"
    org_a_headers = register_user(org_name="Shared Infra Org A", email="shared-infra-a@example.com")
    org_b_headers = register_user(org_name="Shared Infra Org B", email="shared-infra-b@example.com")

    seed_a = _create_and_authorize_asset(client, org_a_headers, ip_a)
    seed_b = _create_and_authorize_asset(client, org_b_headers, ip_b)

    responses = {}
    responses.update(_cymru_responses(ip_a))
    responses.update(_cymru_responses(ip_b))

    def _fake_resolve(self, name, rdtype, *args, **kwargs):
        key = str(name)
        if key not in responses:
            raise dns.resolver.NXDOMAIN()
        return _FakeAnswer(responses[key])

    monkeypatch.setattr(dns.resolver.Resolver, "resolve", _fake_resolve)

    client.post("/discovery/runs", json={"seed_asset_id": seed_a["id"], "provider_name": "cloud"}, headers=org_a_headers)
    client.post("/discovery/runs", json={"seed_asset_id": seed_b["id"], "provider_name": "cloud"}, headers=org_b_headers)

    resp_a = client.get("/assets/shared-infrastructure", headers=org_a_headers)
    body_a = resp_a.json()
    assert len(body_a) == 1
    assert [a["value"] for a in body_a[0]["assets"]] == [ip_a]


def test_all_authenticated_roles_can_read_shared_infrastructure(client, register_user, login_as):
    admin_headers = register_user(email="shared-infra-role-admin@example.com")

    for role, email in (("analyst", "shared-infra-role-analyst@example.com"), ("viewer", "shared-infra-role-viewer@example.com")):
        resp = client.post(
            "/users",
            json={"email": email, "password": "correct-horse-battery", "full_name": role, "role": role},
            headers=admin_headers,
        )
        assert resp.status_code == 201
        role_headers = login_as(email, "correct-horse-battery")
        role_resp = client.get("/assets/shared-infrastructure", headers=role_headers)
        assert role_resp.status_code == 200
