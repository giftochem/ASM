import enum


class UserRole(str, enum.Enum):
    admin = "admin"
    analyst = "analyst"
    viewer = "viewer"


class AssetType(str, enum.Enum):
    domain = "domain"
    subdomain = "subdomain"
    ip_address = "ip_address"
    ip_range = "ip_range"
    url = "url"
    asn = "asn"
    # `service`/`tls_certificate` are reserved, not yet creatable via
    # POST /assets — Step 8.1 already built Service/Certificate as
    # child-detail tables (asset_id FK, rich fields), and adding these as
    # AssetType values today would create a second, thinner
    # representation of the same concept purely so it could be a
    # relationship-graph node. Reconciling "is a Service a relationship
    # node or a child-detail record, or both" is deferred to when a real
    # discovery/correlation step (9-12) actually needs the answer — see
    # app/core/validation.py's normalize_asset_value, which still raises
    # for these. Mirrors how the Technology table existed a full phase
    # before anything populated it.
    service = "service"
    http_endpoint = "http_endpoint"
    tls_certificate = "tls_certificate"
    api = "api"
    cloud_resource = "cloud_resource"
    repository = "repository"
    # Reserved for future Web3 support — not implemented yet. Not
    # creatable via POST /assets (same reasoning as service/
    # tls_certificate above): the enum has room for them so nothing about
    # the relationship model is blocked conceptually, but actually
    # wiring these up is explicitly out of scope for this pass.
    web3_contract = "web3_contract"
    web3_program = "web3_program"
    web3_token = "web3_token"
    web3_wallet = "web3_wallet"
    rpc_endpoint = "rpc_endpoint"


class ScanStatus(str, enum.Enum):
    queued = "queued"
    running = "running"
    completed = "completed"
    failed = "failed"
    cancelled = "cancelled"


class FindingSeverity(str, enum.Enum):
    """A scanner module's qualitative opinion of a single finding — an
    input to the risk engine, not its output. See RiskSeverityBand for the
    aggregate, computed classification; the two are deliberately not the
    same type (a module's per-finding judgment call and a derived score
    classification are different concerns that happen to share a
    5-point-scale shape today, but shouldn't be coupled to the same enum).
    """

    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class RiskSeverityBand(str, enum.Enum):
    """Classification of a computed, aggregate risk_engine score (0-100).
    Distinct from FindingSeverity: this describes a scan's overall
    computed risk posture, not any single finding's raw severity. Kept
    separate so the risk engine's banding can evolve independently of the
    per-finding severity vocabulary every scanner module already depends
    on — e.g. `minimal` exists here for a scan with no meaningful findings,
    a case FindingSeverity's `info` doesn't cleanly represent (info means
    "an observation was made", not "nothing to worry about").
    """

    minimal = "minimal"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class ReportFormat(str, enum.Enum):
    json = "json"
    csv = "csv"
    pdf = "pdf"


class ReportStatus(str, enum.Enum):
    pending = "pending"
    generating = "generating"
    completed = "completed"
    failed = "failed"


class AuditOutcome(str, enum.Enum):
    success = "success"
    failure = "failure"


class LifecycleStatus(str, enum.Enum):
    """Shared across Asset, Service, and Certificate — all three are
    "things ASM currently believes exist," with the same appear/
    disappear dynamic. The state machine that actually drives these
    transitions (time-based staleness, re-observation) is Step 8.3;
    Step 8.1 only defines the states and how new rows default.
    """

    first_seen = "first_seen"
    active = "active"
    stale = "stale"
    disappeared = "disappeared"


class AssetSource(str, enum.Enum):
    """Minimal on purpose: only `manual` is actually produced by any
    code path today. `discovery` is a placeholder for Steps 9-10 to use
    directly or split further (e.g. dns/cert_transparency) via
    ALTER TYPE ... ADD VALUE in a later migration, same as scan_status
    gaining `cancelled` in migration 0002.
    """

    manual = "manual"
    discovery = "discovery"


class AssetEnvironment(str, enum.Enum):
    production = "production"
    staging = "staging"
    development = "development"
    test = "test"
    unknown = "unknown"


class AssetCriticality(str, enum.Enum):
    """Manual/admin-set classification. Step 15 ("Asset Criticality") is
    where automated scoring gets built on top of this — mirrors how
    FindingSeverity (manual, per-module) and RiskSeverityBand (computed)
    already coexist as separate concerns in this codebase.
    """

    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class RelationshipType(str, enum.Enum):
    owns = "owns"
    resolves_to = "resolves_to"
    hosts = "hosts"
    exposes = "exposes"
    uses = "uses"
    belongs_to = "belongs_to"
    interacts_with = "interacts_with"
    deployed_on = "deployed_on"
    served_by = "served_by"
    related_to = "related_to"
    # Step 9.6: an IP's relationship to the ASN that announces it.
    # `belongs_to`'s existing reversal (discovery_normalization_service.
    # _REVERSED_DIRECTION_RELATIONSHIP_TYPES) is calibrated for the
    # opposite hierarchy -- seed=parent, discovered thing=child (e.g. a
    # discovered subdomain belongs_to its seed domain). Here the seed
    # (IP) is the child and the discovered thing (ASN) is the broader
    # container, so reusing belongs_to would reverse to "ASN belongs_to
    # IP" -- backwards. No existing type reads correctly in the default
    # (non-reversed, seed-is-source) direction either, so this one is
    # purpose-built and needs no reversal-set entry: default direction
    # already gives the correct "IP announced_by ASN."
    announced_by = "announced_by"


class ChangeType(str, enum.Enum):
    """Minimal on purpose — only what current code paths actually
    produce (asset/relationship creation and removal). Field-specific
    types (IP_CHANGED, PORT_OPENED, CONTRACT_DEPLOYED, ...) get added via
    ALTER TYPE ... ADD VALUE once the discovery/diffing logic that would
    actually emit them exists (Steps 9+) — same "don't pre-populate an
    enum with values nothing produces yet" principle as AssetSource.
    """

    asset_created = "asset_created"
    asset_updated = "asset_updated"
    asset_status_changed = "asset_status_changed"
    relationship_created = "relationship_created"
    relationship_updated = "relationship_updated"
    relationship_removed = "relationship_removed"
    # Step 9.2: metadata about the seed itself (e.g. DNS TXT records, or
    # a CNAME/MX/NS target outside the authorized scope) that never
    # becomes a new Asset — named specifically rather than reusing
    # asset_updated, matching this codebase's preference for narrow,
    # purpose-built enum values over overloaded ones.
    dns_records_observed = "dns_records_observed"
    # Step 9.3: first time seeing a certificate at an asset+hostname+port
    # slot, vs. its fingerprint differing from what was there before (a
    # rotation event) -- kept distinct so a query can tell "we just
    # started watching this" apart from "this actually changed."
    certificate_observed = "certificate_observed"
    certificate_changed = "certificate_changed"
    # Step 9.4: wildcard/external hostnames found via Certificate
    # Transparency logs that never became an Asset -- named specifically
    # rather than reusing dns_records_observed, since this evidence
    # didn't come from DNS.
    certificate_transparency_observed = "certificate_transparency_observed"
    # Step 9.5: first successful HTTP/HTTPS observation for a given
    # scheme on an asset, vs. a later observation whose evidence
    # (status/server/title/redirect target/security headers/...)
    # differs from the prior one -- same observed-vs-changed distinction
    # certificate_observed/certificate_changed already established.
    http_observed = "http_observed"
    http_changed = "http_changed"
    # Step 9.6: first successful network/ASN observation for an
    # ip_address seed, vs. a later observation whose evidence (ASN/
    # prefix/organization/PTR/cloud classification) differs from the
    # prior one -- same observed-vs-changed distinction as http_observed/
    # http_changed and certificate_observed/certificate_changed.
    network_observed = "network_observed"
    network_changed = "network_changed"
    # Step 9.7: first successful cloud/infrastructure classification for
    # an ip_address seed, vs. a later observation whose classification
    # (provider/confidence/evidence) differs from the prior one -- same
    # observed-vs-changed distinction as network_observed/network_changed.
    infrastructure_observed = "infrastructure_observed"
    infrastructure_changed = "infrastructure_changed"


class AlertType(str, enum.Enum):
    """Step 9.12 -- a small, fixed taxonomy, each backed by a real,
    already-existing signal (see app.services.alert_service's module
    docstring). Deliberately not "dozens of types" -- one per genuinely
    distinct, already-collected intelligence source.

    NOT included: a separate "critical_asset_changed" type keyed on
    ChangeType.asset_updated. Investigated during Step 9.12 and found
    unreachable in the current pipeline:
    discovery_normalization_service._refresh_asset only ever mutates
    last_seen/confidence/status on an existing asset, so its own
    before/after diff can only ever detect a status transition (already
    the dedicated important_asset_reappeared type) -- value/asset_type/
    source/environment/criticality/owner/tags can never differ between
    its two snapshots, since nothing else in the function touches them
    (and there was then no write endpoint for criticality/owner/tags --
    a disclosed gap since Step 8.1/9.5). Shipping a type with no
    reachable trigger would violate this taxonomy's own "only types
    backed by actual existing intelligence" rule, so it was cut rather
    than kept as dead code.

    Stage A.1 made asset_updated reachable: PATCH /assets/{id} records
    one when someone changes an asset's criticality or environment. It
    still maps to no alert type -- that change is the organization's own
    deliberate, audited classification, not new intelligence about the
    asset. Its effect on alerting is indirect: later discovery runs see
    the asset's new priority and business context.
    """

    new_externally_exposed_asset = "new_externally_exposed_asset"
    important_asset_disappeared = "important_asset_disappeared"
    important_asset_reappeared = "important_asset_reappeared"
    certificate_changed = "certificate_changed"
    dns_infrastructure_changed = "dns_infrastructure_changed"
    http_security_posture_changed = "http_security_posture_changed"
    infrastructure_classification_changed = "infrastructure_classification_changed"
    high_priority_asset_detected = "high_priority_asset_detected"
    # The one alert type not sourced from an Observation -- a scheduler-
    # level safety event (Step 9.11's existing auto-disable-on-revoked-
    # authorization behavior), not a discovery-content event.
    authorization_disabled = "authorization_disabled"


class AlertPriority(str, enum.Enum):
    """Deliberately the exact same vocabulary as
    app.services.prioritization_service.PriorityLevel (Step 9.10) -- an
    Alert needs a DB-persisted enum (PriorityLevel itself is
    intentionally NOT persisted, see that module's docstring), so this
    is its persisted mirror, not a second, competing scale.
    """

    informational = "informational"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class AlertStatus(str, enum.Enum):
    open = "open"
    acknowledged = "acknowledged"
    resolved = "resolved"


class NotificationChannel(str, enum.Enum):
    email = "email"


class NotificationStatus(str, enum.Enum):
    pending = "pending"
    sending = "sending"
    sent = "sent"
    failed_transient = "failed_transient"
    failed_permanent = "failed_permanent"


class DiscoveryRunStatus(str, enum.Enum):
    """Kept as its own type rather than reusing ScanStatus, even though
    the shape is identical — same reasoning as FindingSeverity vs.
    RiskSeverityBand: passive discovery and active scanning are
    deliberately separate concerns that happen to share a vocabulary
    today, not one thing wearing two names.
    """

    queued = "queued"
    running = "running"
    completed = "completed"
    failed = "failed"
    cancelled = "cancelled"


class DiscoveryResultOutcome(str, enum.Enum):
    created = "created"
    refreshed = "refreshed"
    rejected = "rejected"
    # Step 9.2: the candidate was metadata about the seed itself (see
    # ChangeType.dns_records_observed) -- recorded, but never produced or
    # matched an Asset.
    observed = "observed"
    # Step 9.3: re-observed the same certificate (fingerprint unchanged)
    # -- last_seen bumped, but nothing meaningful happened, so no new
    # Observation is written for this one. Distinct from `refreshed`,
    # which for certificates means the fingerprint actually rotated.
    unchanged = "unchanged"
    # Step 9.5: a scheme attempt failed at the network level (timeout,
    # connection refused, TLS failure, DNS failure) -- distinct from
    # `rejected`, which means a candidate/observation failed a
    # validation or authorization-scope check, not a network error.
    failed = "failed"
