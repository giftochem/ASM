"""Unit tests for the discovery provider abstraction/registry — no DB, no
HTTP client, mirrors how a real scanner module's registry would be
tested in isolation.
"""

from app.core.enums import AssetType, RelationshipType
from app.discovery.registry import all_provider_names, get_provider
from app.discovery.stub_provider import StubDiscoveryProvider


def test_stub_provider_is_registered():
    assert "stub" in all_provider_names()
    assert isinstance(get_provider("stub"), StubDiscoveryProvider)


def test_unknown_provider_returns_none():
    assert get_provider("does-not-exist") is None


def test_stub_provider_supports_domain_and_subdomain_only():
    provider = StubDiscoveryProvider()
    assert provider.supports(AssetType.domain) is True
    assert provider.supports(AssetType.subdomain) is True
    assert provider.supports(AssetType.ip_address) is False
    assert provider.supports(AssetType.url) is False


def test_stub_provider_returns_deterministic_candidate():
    provider = StubDiscoveryProvider()
    result = provider.discover("example.com")

    assert result.provider == "stub"
    assert result.error is None
    assert len(result.candidates) == 1
    candidate = result.candidates[0]
    assert candidate.asset_type == AssetType.subdomain
    assert candidate.value == "www.example.com"
    assert candidate.relationship_type == RelationshipType.belongs_to
    assert 0.0 < candidate.confidence <= 1.0


def test_stub_provider_is_deterministic_across_calls():
    provider = StubDiscoveryProvider()
    first = provider.discover("example.com")
    second = provider.discover("example.com")
    assert first.candidates[0].value == second.candidates[0].value


# --- Step 9.13: GET /discovery/providers -------------------------------------


def test_providers_endpoint_requires_authentication(client):
    resp = client.get("/discovery/providers")
    assert resp.status_code == 401


def test_providers_endpoint_lists_every_registered_provider(client, register_user):
    headers = register_user(email="providers-list@example.com")
    resp = client.get("/discovery/providers", headers=headers)
    assert resp.status_code == 200
    body = resp.json()

    names = {p["name"] for p in body}
    assert names == set(all_provider_names())

    stub_entry = next(p for p in body if p["name"] == "stub")
    assert set(stub_entry["applicable_seed_types"]) == {"domain", "subdomain"}
    assert stub_entry["depends_on"] == []


def test_providers_endpoint_reflects_declared_dependency(client, register_user):
    """cloud_provider.py declares depends_on={"network"} (Step 9.11.6) --
    confirmed here it's actually surfaced through the API, not just
    present on the Python class.
    """
    headers = register_user(email="providers-depends@example.com")
    body = client.get("/discovery/providers", headers=headers).json()
    cloud_entry = next(p for p in body if p["name"] == "cloud")
    assert cloud_entry["depends_on"] == ["network"]
    assert cloud_entry["applicable_seed_types"] == ["ip_address"]


def test_providers_endpoint_is_identical_across_organizations(client, register_user):
    """This catalog is not org-scoped data -- two different orgs must see
    the exact same list (unlike every other endpoint in this API)."""
    headers_a = register_user(email="providers-org-a@example.com", org_name="Providers Org A")
    headers_b = register_user(email="providers-org-b@example.com", org_name="Providers Org B")

    body_a = client.get("/discovery/providers", headers=headers_a).json()
    body_b = client.get("/discovery/providers", headers=headers_b).json()
    assert body_a == body_b
