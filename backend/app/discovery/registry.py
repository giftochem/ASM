from app.config import is_test_tooling_environment, settings
from app.discovery.base import DiscoveryProvider
from app.discovery.certificate_provider import CertificateDiscoveryProvider
from app.discovery.cloud_provider import CloudDiscoveryProvider
from app.discovery.dns_provider import DNSDiscoveryProvider
from app.discovery.http_provider import HttpDiscoveryProvider
from app.discovery.network_provider import NetworkDiscoveryProvider
from app.discovery.stub_provider import StubDiscoveryProvider
from app.discovery.subdomain_provider import SubdomainDiscoveryProvider

# Every provider this codebase knows about, keyed by name -- INCLUDING
# test-only ones (DiscoveryProvider.test_only, e.g. `stub`), so tests can
# reach their classes directly. This is not the set a deployment may
# actually use: anything user-facing or execution-facing must go through
# get_provider()/available_providers()/all_provider_names() below, which
# apply availability. Never iterate this dict for those purposes.
DISCOVERY_PROVIDER_REGISTRY: dict[str, DiscoveryProvider] = {
    provider.name: provider
    for provider in (
        StubDiscoveryProvider(),
        DNSDiscoveryProvider(),
        CertificateDiscoveryProvider(),
        SubdomainDiscoveryProvider(),
        HttpDiscoveryProvider(),
        NetworkDiscoveryProvider(),
        CloudDiscoveryProvider(),
    )
}


def allows_test_only_providers() -> bool:
    """Read at call time (not import time) so the setting can't be baked
    in by whichever module happened to import first. Only an allowlisted
    non-production ENVIRONMENT permits them, whatever the flag says --
    production, or any unrecognized value, fails closed."""
    return settings.enable_test_discovery_providers and is_test_tooling_environment(settings.environment)


def _is_available(provider: DiscoveryProvider) -> bool:
    return not provider.test_only or allows_test_only_providers()


def get_provider(name: str) -> DiscoveryProvider | None:
    """None both for an unknown name and for a test-only provider that
    isn't enabled -- every run/schedule validation path already rejects
    None as an unknown provider, so a disabled test-only provider is
    indistinguishable from one that doesn't exist."""
    provider = DISCOVERY_PROVIDER_REGISTRY.get(name)
    if provider is None or not _is_available(provider):
        return None
    return provider


def available_providers() -> list[DiscoveryProvider]:
    return [provider for provider in DISCOVERY_PROVIDER_REGISTRY.values() if _is_available(provider)]


def all_provider_names() -> list[str]:
    return [provider.name for provider in available_providers()]
