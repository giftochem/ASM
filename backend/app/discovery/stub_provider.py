from app.core.enums import AssetType, RelationshipType
from app.discovery.base import DiscoveryCandidate, DiscoveryProvider, DiscoveryProviderResult


class StubDiscoveryProvider(DiscoveryProvider):
    """Deterministic, zero-network-I/O provider that exists solely to
    prove the discovery orchestration/normalization architecture end to
    end — NOT a real discovery mechanism. The first real provider (DNS/
    subdomain/certificate/HTTP) is explicit future work (Step 9.2+).

    Given a domain/subdomain seed, always reports exactly one candidate:
    a `www.` subdomain of the seed, related back to it via `belongs_to`.

    TEST-ONLY: its candidate has no real evidence behind it, so it must
    never produce assets in a real organization. Unavailable (absent from
    the catalog, rejected by every run/schedule path) unless
    settings.enable_test_discovery_providers is explicitly on -- see
    app/discovery/registry.py.
    """

    name = "stub"
    applicable_seed_types = {AssetType.domain, AssetType.subdomain}
    test_only = True

    def discover(self, seed_value: str) -> DiscoveryProviderResult:
        candidate = DiscoveryCandidate(
            asset_type=AssetType.subdomain,
            value=f"www.{seed_value}",
            relationship_type=RelationshipType.belongs_to,
            confidence=0.9,
            evidence={"note": "deterministic stub candidate — not a real discovery result"},
        )
        return DiscoveryProviderResult(provider=self.name, candidates=[candidate])
