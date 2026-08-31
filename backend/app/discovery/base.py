"""Common interface every discovery provider implements — deliberately
mirrors app.scanners.base's ScannerModule/ScanModuleResult shape.

Providers never decide for themselves whether they're allowed to run —
that gate (authorization_confirmed on the seed Asset) is enforced by
app.services.discovery_service, exactly like scan_service enforces it
for scanner modules. A provider's job is just: given an already-
validated seed value, return discovery candidates plus any evidence.

Providers that connect to the SEED's own infrastructure (a destination
the scan target effectively controls, e.g. via DNS) must reuse the
existing SSRF-safe fetch layer (app.scanners.net_safety / http_client /
pinned_transport) rather than opening their own unvalidated connection —
app.discovery.certificate_provider (Step 9.3) does exactly this. A
provider that only ever talks to a fixed, trusted third party (the seed
value used merely as a query parameter, never a connection destination —
e.g. app.discovery.subdomain_provider's Certificate Transparency lookup,
Step 9.4) doesn't have that threat model and doesn't need it; see that
module's own docstring for the reasoning.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import ClassVar

from app.core.enums import AssetType, ChangeType, RelationshipType


@dataclass
class DiscoveryCandidate:
    """One discovered thing — could become a new Asset, or corroborate
    an existing one. `relationship_type`, if set, is how this candidate
    relates back to the seed asset (e.g. a subdomain `belongs_to` its
    parent domain); `None` means "just note this exists," no edge drawn.
    """

    asset_type: AssetType
    value: str
    relationship_type: RelationshipType | None = None
    confidence: float = 1.0
    evidence: dict = field(default_factory=dict)


@dataclass
class CertificateObservation:
    """What a certificate-retrieving provider reports about one TLS
    certificate (Step 9.3). Kept as its own typed dataclass, not a plain
    dict -- this is structured, multi-field data (mirrors why
    DiscoveryCandidate itself is a dataclass, not a dict). `in_scope_sans`
    and `external_sans` are the already-classified split (via
    app.core.validation.is_hostname_in_scope against the seed) -- the
    provider does this classification, not the normalization layer,
    since only the provider knows what raw SAN list it saw.
    """

    hostname: str
    port: int
    fingerprint_sha256: str
    issuer: str | None = None
    subject: str | None = None
    valid_from: datetime | None = None
    valid_until: datetime | None = None
    serial_number: str | None = None
    signature_algorithm: str | None = None
    protocol_version: str | None = None
    cipher_suite: str | None = None
    subject_alt_names: list[str] = field(default_factory=list)
    is_expired: bool = False
    is_self_signed: bool = False
    certificate_version: str | None = None
    public_key_algorithm: str | None = None
    public_key_size: int | None = None
    in_scope_sans: list[str] = field(default_factory=list)
    external_sans: list[str] = field(default_factory=list)
    confidence: float = 1.0


@dataclass
class HttpObservation:
    """What one scheme attempt (https or http) against a seed reported
    (Step 9.5). A domain/subdomain seed produces two of these
    (independent https/http attempts); a url seed produces exactly one,
    for its own scheme. Kept as its own typed dataclass, matching
    CertificateObservation's precedent for structured provider output.

    `left_authorized_scope`/`external_redirect_host` cover the case
    where the final redirect destination is outside the seed's
    authorized scope (app.core.validation.is_hostname_in_scope) -- when
    True, `server`/`title`/`security_headers`/`technology_evidence`
    are left at their defaults: that destination's data is never
    attributed to the org. Deliberately carries no cookie *values* and
    no raw response body -- `cookie_security_flags` holds only
    attribute booleans (secure/httponly/samesite), never name=value.
    """

    scheme: str
    requested_url: str
    succeeded: bool = True
    failure_reason: str | None = None
    left_authorized_scope: bool = False
    external_redirect_host: str | None = None
    final_url: str | None = None
    status_code: int | None = None
    content_type: str | None = None
    redirect_count: int = 0
    server: str | None = None
    x_powered_by: str | None = None
    title: str | None = None
    security_headers: dict[str, bool] = field(default_factory=dict)
    cookie_security_flags: list[dict] = field(default_factory=list)
    technology_evidence: list[dict] = field(default_factory=list)
    confidence: float = 1.0


@dataclass
class NetworkObservation:
    """What the network/ASN provider (Step 9.6) reports about one
    ip_address seed. Exactly one per run (unlike HttpObservation's
    per-scheme list) -- there is only one IP to look up.

    `rejected` covers a seed that failed the provider's own
    defense-in-depth safety re-check (private/loopback/link-local/
    reserved -- should already be unreachable via the normal asset-
    creation path, but re-checked here anyway); `succeeded=False`
    covers a genuine lookup failure (no data returned from any source).
    `ptr_hostname` is evidence only -- see network_provider.py's module
    docstring for why this provider never promotes it to a candidate
    Asset. `cloud_provider_evidence`, if set, is a labeled *inference*
    from the AS organization name, kept separate from `asn_organization`
    (the registry-reported fact) so the two are never conflated.
    """

    ip: str
    ip_version: int
    succeeded: bool = True
    rejected: bool = False
    rejection_reason: str | None = None
    failure_reason: str | None = None
    asn: str | None = None
    asn_organization: str | None = None
    announced_prefix: str | None = None
    network_country: str | None = None
    registry: str | None = None
    ptr_hostname: str | None = None
    cloud_provider_evidence: dict | None = None
    confidence: float = 1.0


@dataclass
class InfrastructureProviderData:
    """Fresh network signals for one ip_address seed, gathered by
    composing NetworkDiscoveryProvider rather than re-querying Team
    Cymru independently (Step 9.7) -- see cloud_provider.py's module
    docstring. Deliberately carries no HTTP/TLS fields: those are
    already stored (from Steps 9.3/9.5, on hostnames that resolve_to
    this IP) and are read by discovery_normalization_service, which has
    DB access; providers themselves don't.
    """

    ip: str
    succeeded: bool = True
    rejected: bool = False
    rejection_reason: str | None = None
    failure_reason: str | None = None
    asn: str | None = None
    asn_organization: str | None = None
    announced_prefix: str | None = None
    ptr_hostname: str | None = None


@dataclass
class DiscoveryProviderResult:
    provider: str
    candidates: list[DiscoveryCandidate] = field(default_factory=list)
    # Same "never raise, report instead" contract as ScanModuleResult.error
    # — one misbehaving provider must not abort discovery orchestration.
    error: str | None = None
    # Metadata about the SEED itself (e.g. DNS TXT records, or a
    # CNAME/MX/NS target outside the authorized scope) that should become
    # an Observation on the seed, never a new Asset -- optional, additive
    # (Step 9.2); existing providers that don't set it are unaffected.
    seed_evidence: dict | None = None
    # A retrieved TLS certificate (Step 9.3) -- optional, additive, same
    # pattern as seed_evidence. Populates the existing Certificate
    # child-detail table via discovery_normalization_service, not a new
    # Asset/graph node.
    certificate_data: CertificateObservation | None = None
    # Which ChangeType record_seed_evidence should use for `seed_evidence`
    # above (Step 9.4) -- defaults to the original Step 9.2 value so the
    # DNS provider (which never sets this) is unaffected; a provider
    # whose evidence isn't DNS-sourced should set this explicitly rather
    # than have it mislabeled.
    seed_evidence_change_type: ChangeType = ChangeType.dns_records_observed
    # Independent per-scheme HTTP/HTTPS observations (Step 9.5) --
    # optional, additive, same pattern as the two fields above; existing
    # providers that don't set it are unaffected (empty list default).
    http_observations: list[HttpObservation] = field(default_factory=list)
    # Network/ASN intelligence about the seed ip_address (Step 9.6) --
    # optional, additive, same pattern as certificate_data. Populates an
    # Observation on the seed IP (via discovery_normalization_service)
    # and, unlike certificate_data, may also carry ASN DiscoveryCandidates
    # (see NetworkDiscoveryProvider) processed through the normal
    # candidate pipeline exactly like any other provider's candidates.
    network_data: NetworkObservation | None = None
    # Fresh network signals for cloud/infrastructure classification
    # (Step 9.7) -- optional, additive, same pattern as the fields
    # above. See InfrastructureProviderData and cloud_provider.py.
    infrastructure_data: InfrastructureProviderData | None = None


class DiscoveryProvider(ABC):
    name: ClassVar[str]
    applicable_seed_types: ClassVar[set[AssetType]]
    # Step 9.11: names of OTHER providers whose evidence improves this
    # one's results -- e.g. "cloud" names "network" because the ASN
    # Asset/relationship the graph gets is only ever created by
    # NetworkDiscoveryProvider's own candidate (CloudDiscoveryProvider
    # composes network internally for its OWN classification but never
    # produces that candidate itself, see cloud_provider.py). This is
    # NOT a hard requirement the provider enforces (every provider still
    # degrades gracefully with zero prior data, per every provider's own
    # "never hard-fail" contract) -- it's an orchestration-level hint,
    # checked by discovery_scheduler_executor as "has this provider ever
    # completed successfully for this seed," not a live dependency graph.
    # Deliberately not a DAG: no transitive resolution, no cycle
    # detection needed for a plain set of names checked by simple
    # existence query.
    depends_on: ClassVar[set[str]] = set()

    def supports(self, asset_type: AssetType) -> bool:
        return asset_type in self.applicable_seed_types

    @abstractmethod
    def discover(self, seed_value: str) -> DiscoveryProviderResult:
        """Execute against an already-validated, already-authorized seed
        value. Must not raise for expected failure modes (seed
        unreachable, nothing found, etc.) — return a
        DiscoveryProviderResult with `error` set instead, so one failing
        provider can't take down the whole run.
        """
        raise NotImplementedError
