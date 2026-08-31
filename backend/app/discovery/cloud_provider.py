"""Cloud/infrastructure classification for an authorized ip_address seed
(Step 9.7). Answers: what cloud/hosting provider appears to support
this address, with what evidence and confidence -- correlating signals
already known to ASM rather than probing anything new.

ARCHITECTURE DECISION -- ip_address seeds only, not domain/subdomain/
url. Steps 9.2/9.5 already turn a domain/subdomain/url seed into an
ip_address Asset (via DNS resolution) and HTTP/TLS evidence on that
hostname; Step 9.6 already turns an ip_address seed into ASN/prefix/PTR
evidence. Accepting domain/subdomain/url here too would mean either
duplicating that whole resolution pipeline, or silently resolving to
"the first IP" and hiding which address the classification actually
describes (a domain can resolve to several). The existing, correct
pipeline is: resolve/discover down to an IP first (dns/http/network),
*then* classify that IP's infrastructure -- exactly the seed-type
restriction this provider enforces.

NO NEW NETWORK I/O OF ITS OWN for the strongest signals: this provider
composes NetworkDiscoveryProvider directly (calling it, not
reimplementing its Team Cymru queries) for ASN/prefix/PTR, and produces
no DiscoveryCandidate of its own -- ASN-as-Asset creation stays
entirely network_provider's responsibility, so running "cloud"
discovery never duplicates or fights over that. HTTP Server-header and
TLS-issuer evidence come from *already-stored* Observation/Certificate
rows (via discovery_normalization_service, which has DB access this
provider doesn't) rather than a fresh HTTP/TLS connection -- this
provider does not open a socket to the target at all.

CLOUD RESOURCE ASSET DECISION: no new Asset, no new relationship type.
"This IP is probably fronted by Cloudflare" does not identify a unique,
addressable cloud resource the way a discovered hostname or a
certificate's fingerprint does -- there's no ARN, no instance ID, no
stable identifier, just a probabilistic classification of the IP
already sitting in the graph. Recording it as Observation evidence
(mirroring Step 9.6's own prefix/organization/country precedent)
represents this honestly; inventing a "cloud_resource" Asset per
provider guess would imply a precision this evidence doesn't have.
"""

from app.core.enums import AssetType
from app.discovery.base import DiscoveryProvider, DiscoveryProviderResult, InfrastructureProviderData
from app.discovery.network_provider import NetworkDiscoveryProvider


class CloudDiscoveryProvider(DiscoveryProvider):
    name = "cloud"
    applicable_seed_types = {AssetType.ip_address}
    # Step 9.11: not a hard technical requirement (discover() above
    # composes NetworkDiscoveryProvider directly and works standalone)
    # -- but network_provider is the ONLY provider whose own candidate
    # pipeline creates the ASN Asset/announced_by relationship in the
    # graph; cloud_provider never produces a candidate of its own (see
    # this module's docstring). Declaring the dependency means
    # orchestration prefers network to have run at least once first, so
    # scheduled cloud classification doesn't silently leave the ASN
    # permanently missing from the graph.
    depends_on = {"network"}

    def discover(self, seed_value: str) -> DiscoveryProviderResult:
        network_result = NetworkDiscoveryProvider().discover(seed_value)
        if network_result.error is not None:
            return DiscoveryProviderResult(provider=self.name, error=network_result.error)

        network_data = network_result.network_data
        if network_data is None:
            return DiscoveryProviderResult(
                provider=self.name,
                infrastructure_data=InfrastructureProviderData(ip=seed_value, succeeded=False, failure_reason="no network data available"),
            )

        if network_data.rejected:
            return DiscoveryProviderResult(
                provider=self.name,
                infrastructure_data=InfrastructureProviderData(
                    ip=seed_value, rejected=True, rejection_reason=network_data.rejection_reason
                ),
            )

        return DiscoveryProviderResult(
            provider=self.name,
            infrastructure_data=InfrastructureProviderData(
                ip=seed_value,
                succeeded=network_data.succeeded,
                failure_reason=network_data.failure_reason if not network_data.succeeded else None,
                asn=network_data.asn,
                asn_organization=network_data.asn_organization,
                announced_prefix=network_data.announced_prefix,
                ptr_hostname=network_data.ptr_hostname,
            ),
        )
