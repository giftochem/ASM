from app.discovery.base import DiscoveryProvider
from app.discovery.certificate_provider import CertificateDiscoveryProvider
from app.discovery.cloud_provider import CloudDiscoveryProvider
from app.discovery.dns_provider import DNSDiscoveryProvider
from app.discovery.http_provider import HttpDiscoveryProvider
from app.discovery.network_provider import NetworkDiscoveryProvider
from app.discovery.stub_provider import StubDiscoveryProvider
from app.discovery.subdomain_provider import SubdomainDiscoveryProvider

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


def get_provider(name: str) -> DiscoveryProvider | None:
    return DISCOVERY_PROVIDER_REGISTRY.get(name)


def all_provider_names() -> list[str]:
    return list(DISCOVERY_PROVIDER_REGISTRY.keys())
