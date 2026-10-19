"""Relationship traversal semantics (Stage A.2) -- which stored
relationships an attack-path walk may follow, in which direction, and
why. Deliberately small and fail-closed: a relationship type that isn't
explicitly allowed here is never followed, and every decision carries
the rule and reason that produced it.

The MVP rules, from how relationships are actually stored:

- `resolves_to` (dns provider: A/AAAA -> ip_address, CNAME -> hostname;
  stored hostname -> target): followed forward only, from a domain/
  subdomain to the IP or hostname it resolves to, and only as an
  observed DNS fact -- the row must come from discovery AND a completed
  `dns` discovery run in this organization must have recorded exactly
  that resolution (the run's seed is the relationship's source, the
  result's asset is its target). A manually entered `resolves_to` is an
  analyst assertion, not an observed DNS fact, and v0.1 never follows
  it, audit trail or not. (create_relationship never rewrites `source`
  on re-confirmation, so a manual row discovery later re-observed stays
  manual -- and stays rejected; conservative, and documented.)
- `hosts` / `exposes` (no provider produces these; only
  POST /assets/{id}/relationships does): followed forward only when the
  row is analyst-entered (source=manual) AND its creation is visible in
  the audit log (`asset.relationship.create` for that relationship, in
  this organization) -- the provenance is returned with the decision.
- Everything else is never followed: `related_to` (certificate SAN
  co-occurrence), `announced_by` (shared ASN), `served_by`/`uses`
  (NS/MX -- shared providers), `belongs_to`/`owns` (ownership, not
  reachability), `deployed_on`/`interacts_with` (no MVP semantics).
  Sharing an IP, certificate, ASN or cloud provider is never evidence
  of compromise or lateral movement.

Also rejected whatever the type: reverse traversal (target -> source),
a relationship that is stale/disappeared, an endpoint asset that is
disappeared or deactivated, and any relationship whose endpoints aren't
both in the requesting organization. Confidence is never consulted, and
nothing here says anything about exploitability.

Given an assessment time (`as_of`), evidence is point-in-time -- audit
records and DNS results written later are ignored -- and with a
`dns_freshness_window` a resolves_to is followed only when its DNS
evidence is no older than the window (rule `dns_evidence_stale`
otherwise). The path engine (attack_path_service) always passes both;
lifecycle status itself is current stored state, not reconstructed.
"""

import enum
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.core.enums import (
    AssetSource,
    AssetType,
    DiscoveryResultOutcome,
    DiscoveryRunStatus,
    LifecycleStatus,
    RelationshipType,
)
from app.models.asset import Asset
from app.models.asset_relationship import AssetRelationship
from app.models.audit_log import AuditLog
from app.models.discovery_result import DiscoveryResult
from app.models.discovery_run import DiscoveryRun

RELATIONSHIP_CREATE_AUDIT_ACTION = "asset.relationship.create"
DNS_PROVIDER = "dns"
# Outcomes for a candidate that became (or re-confirmed) its asset and
# relationship; `rejected` candidates never created either.
_DNS_ACCEPTED_OUTCOMES = (
    DiscoveryResultOutcome.created,
    DiscoveryResultOutcome.refreshed,
    DiscoveryResultOutcome.unchanged,
)

_ACTIVE_RELATIONSHIP_STATUSES = {LifecycleStatus.active, LifecycleStatus.first_seen}
_HOSTNAME_TYPES = {AssetType.domain, AssetType.subdomain}
_RESOLUTION_TARGET_TYPES = {AssetType.ip_address, AssetType.domain, AssetType.subdomain}


class TypeRule(str, enum.Enum):
    dns_resolution = "dns_resolution"  # followed forward
    analyst_entered_only = "analyst_entered_only"  # followed forward with visible analyst provenance
    never = "never"


# Exhaustive on purpose: tests assert every RelationshipType appears
# here, so a new type can't be followed (or silently ignored) without a
# deliberate decision.
TYPE_RULES: dict[RelationshipType, tuple[TypeRule, str]] = {
    RelationshipType.resolves_to: (TypeRule.dns_resolution, "DNS resolution"),
    RelationshipType.hosts: (TypeRule.analyst_entered_only, "analyst-entered hosting"),
    RelationshipType.exposes: (TypeRule.analyst_entered_only, "analyst-entered exposure"),
    RelationshipType.related_to: (
        TypeRule.never,
        "generic association (e.g. shared certificate SANs) -- not reachability",
    ),
    RelationshipType.announced_by: (
        TypeRule.never,
        "shared infrastructure (ASN announcement) -- not reachability or lateral movement",
    ),
    RelationshipType.served_by: (
        TypeRule.never,
        "shared infrastructure (DNS name servers) -- not reachability or lateral movement",
    ),
    RelationshipType.uses: (
        TypeRule.never,
        "shared infrastructure (e.g. mail exchangers) -- not reachability or lateral movement",
    ),
    RelationshipType.belongs_to: (TypeRule.never, "ownership hierarchy -- not reachability"),
    RelationshipType.owns: (TypeRule.never, "ownership -- not reachability"),
    RelationshipType.deployed_on: (TypeRule.never, "no attack-path semantics defined for the MVP"),
    RelationshipType.interacts_with: (TypeRule.never, "no attack-path semantics defined for the MVP"),
}


@dataclass(frozen=True)
class DnsResolutionEvidence:
    """The stored dns discovery result backing a `resolves_to` --
    the latest one, when several runs recorded it."""

    result_id: uuid.UUID
    discovery_run_id: uuid.UUID
    observed_at: datetime
    record_type: str | None  # "A" / "AAAA" / "CNAME", as the provider stored it


@dataclass(frozen=True)
class RelationshipProvenance:
    source: str  # the row's AssetSource
    entered_by_user_id: uuid.UUID | None = None
    entered_at: datetime | None = None
    audit_log_id: uuid.UUID | None = None
    dns_evidence: DnsResolutionEvidence | None = None


@dataclass(frozen=True)
class TraversalDecision:
    relationship_id: uuid.UUID
    relationship_type: str
    source_asset_id: uuid.UUID
    target_asset_id: uuid.UUID
    from_asset_id: uuid.UUID
    to_asset_id: uuid.UUID | None  # where following it would lead; None when not incident on from_asset
    direction: str  # "forward" | "reverse" | "not_incident"
    allowed: bool
    rule: str  # machine-readable code for the deciding rule
    reason: str
    provenance: RelationshipProvenance


def evaluate_traversal(
    relationship: AssetRelationship,
    *,
    from_asset_id: uuid.UUID,
    organization_id: uuid.UUID,
    source_asset: Asset | None,
    target_asset: Asset | None,
    audit_entry: AuditLog | None = None,
    dns_evidence: DnsResolutionEvidence | None = None,
    as_of: datetime | None = None,
    dns_freshness_window: timedelta | None = None,
) -> TraversalDecision:
    """Pure decision for one relationship, walked from `from_asset_id`.
    `source_asset`/`target_asset` are the relationship's endpoints as
    loaded (None if missing); `audit_entry` is its creation audit record
    and `dns_evidence` the dns discovery result recording exactly this
    resolution, if any (evaluate_asset_relationships loads both,
    organization-scoped).

    With `as_of`, evaluation is point-in-time for evidence: an audit
    record or DNS result written after `as_of` is ignored. With
    `dns_freshness_window` too, a resolves_to is only followed when its
    DNS evidence is no older than the window at `as_of` -- an old
    observation is not treated as current just because the relationship
    row is still active. Without them, behavior is unchanged."""
    if as_of is not None:
        if audit_entry is not None and audit_entry.created_at > as_of:
            audit_entry = None
        if dns_evidence is not None and dns_evidence.observed_at > as_of:
            dns_evidence = None
    provenance = RelationshipProvenance(
        source=relationship.source.value,
        entered_by_user_id=audit_entry.user_id if audit_entry is not None else None,
        entered_at=audit_entry.created_at if audit_entry is not None else None,
        audit_log_id=audit_entry.id if audit_entry is not None else None,
        dns_evidence=dns_evidence,
    )
    if from_asset_id == relationship.source_asset_id:
        direction, to_asset_id = "forward", relationship.target_asset_id
    elif from_asset_id == relationship.target_asset_id:
        direction, to_asset_id = "reverse", relationship.source_asset_id
    else:
        direction, to_asset_id = "not_incident", None

    def decide(allowed: bool, rule: str, reason: str) -> TraversalDecision:
        return TraversalDecision(
            relationship_id=relationship.id,
            relationship_type=relationship.relationship_type.value,
            source_asset_id=relationship.source_asset_id,
            target_asset_id=relationship.target_asset_id,
            from_asset_id=from_asset_id,
            to_asset_id=to_asset_id,
            direction=direction,
            allowed=allowed,
            rule=rule,
            reason=reason,
            provenance=provenance,
        )

    endpoints = (source_asset, target_asset)
    if any(asset is None or asset.organization_id != organization_id for asset in endpoints):
        return decide(False, "cross_organization", "both endpoints must belong to the requesting organization")
    if source_asset.id != relationship.source_asset_id or target_asset.id != relationship.target_asset_id:
        return decide(False, "endpoint_mismatch", "the loaded endpoints don't match the relationship")
    if direction == "not_incident":
        return decide(False, "not_incident", "the relationship doesn't touch the asset being walked from")
    if direction == "reverse":
        return decide(False, "reverse_traversal", "relationships are only followed from source to target")
    if relationship.status not in _ACTIVE_RELATIONSHIP_STATUSES:
        return decide(
            False, "relationship_inactive", f"the relationship is {relationship.status.value}, not currently observed"
        )
    for asset in endpoints:
        if not asset.is_active:
            return decide(False, "endpoint_inactive", f"asset {asset.id} is deactivated")
        if asset.status is LifecycleStatus.disappeared:
            return decide(False, "endpoint_inactive", f"asset {asset.id} is marked disappeared")

    type_rule, meaning = TYPE_RULES.get(
        relationship.relationship_type, (TypeRule.never, "no attack-path semantics defined for the MVP")
    )
    if type_rule is TypeRule.never:
        return decide(False, "type_not_traversable", f"'{relationship.relationship_type.value}' is {meaning}")

    if type_rule is TypeRule.dns_resolution:
        if relationship.source is not AssetSource.discovery:
            return decide(
                False,
                "dns_not_observed",
                f"this resolves_to was entered by an analyst ({relationship.source.value}): an assertion, not an "
                f"observed DNS fact, so v0.1 doesn't follow it",
            )
        if source_asset.asset_type not in _HOSTNAME_TYPES or target_asset.asset_type not in _RESOLUTION_TARGET_TYPES:
            return decide(
                False,
                "resolution_endpoint_types",
                f"resolves_to must lead from a domain/subdomain to an IP or hostname, not "
                f"{source_asset.asset_type.value} -> {target_asset.asset_type.value}",
            )
        if dns_evidence is None:
            return decide(
                False,
                "dns_evidence_missing",
                f"no completed {DNS_PROVIDER} discovery run in this organization recorded {source_asset.value} "
                f"resolving to {target_asset.value}",
            )
        if as_of is not None and dns_freshness_window is not None and as_of - dns_evidence.observed_at > dns_freshness_window:
            return decide(
                False,
                "dns_evidence_stale",
                f"the latest {DNS_PROVIDER} discovery result recording {source_asset.value} resolving to "
                f"{target_asset.value} is from {dns_evidence.observed_at.isoformat()}, more than {dns_freshness_window} "
                f"before the assessment time",
            )
        record = f"{dns_evidence.record_type} record" if dns_evidence.record_type else "record"
        return decide(
            True,
            "dns_resolution_forward",
            f"{source_asset.value} resolves to {target_asset.value} ({meaning}: {DNS_PROVIDER} discovery recorded the "
            f"{record} at {dns_evidence.observed_at.isoformat()}, result {dns_evidence.result_id}; followed forward only)",
        )

    # TypeRule.analyst_entered_only
    if relationship.source is not AssetSource.manual:
        return decide(
            False,
            "not_analyst_entered",
            f"'{relationship.relationship_type.value}' is only followed when an analyst entered it; this one came from "
            f"{relationship.source.value}",
        )
    if audit_entry is None or audit_entry.user_id is None:
        return decide(
            False,
            "provenance_not_visible",
            f"no '{RELATIONSHIP_CREATE_AUDIT_ACTION}' audit record shows who entered this relationship",
        )
    return decide(
        True,
        "analyst_entered_forward",
        # Who entered it stays in the (admin-only) audit record and in
        # `provenance` for internal callers -- never in this
        # user-facing explanation.
        f"{meaning}: {source_asset.value} -> {target_asset.value}, entered by an analyst at "
        f"{audit_entry.created_at.isoformat()} (audit record {audit_entry.id}; followed forward only)",
    )


def evaluate_asset_relationships(
    db: Session,
    organization_id: uuid.UUID,
    asset_id: uuid.UUID,
    *,
    as_of: datetime | None = None,
    dns_freshness_window: timedelta | None = None,
) -> list[TraversalDecision]:
    """A decision for every relationship touching `asset_id` (outgoing as
    forward, incoming as reverse), walked from that asset. Empty when the
    asset isn't in this organization. A fixed number of queries.
    `as_of`/`dns_freshness_window`: see evaluate_traversal."""
    from_asset = db.query(Asset).filter(Asset.id == asset_id, Asset.organization_id == organization_id).one_or_none()
    if from_asset is None:
        return []
    relationships = (
        db.query(AssetRelationship)
        .filter(or_(AssetRelationship.source_asset_id == asset_id, AssetRelationship.target_asset_id == asset_id))
        .all()
    )
    decisions = _evaluate_pairs(
        db,
        organization_id,
        [(relationship, asset_id) for relationship in relationships],
        as_of=as_of,
        dns_freshness_window=dns_freshness_window,
    )
    return sorted(decisions, key=lambda d: (d.direction, d.relationship_type, str(d.relationship_id)))


def evaluate_forward_traversals(
    db: Session,
    organization_id: uuid.UUID,
    relationships: list[AssetRelationship],
    *,
    as_of: datetime | None = None,
    dns_freshness_window: timedelta | None = None,
) -> list[TraversalDecision]:
    """Each relationship evaluated from its own source -- the forward
    decision a path search needs for every relationship it considers at
    one level. The same rules as evaluate_asset_relationships, batched:
    a fixed number of queries however many relationships are passed.
    Decisions come back in input order."""
    return _evaluate_pairs(
        db,
        organization_id,
        [(relationship, relationship.source_asset_id) for relationship in relationships],
        as_of=as_of,
        dns_freshness_window=dns_freshness_window,
    )


def _evaluate_pairs(
    db: Session,
    organization_id: uuid.UUID,
    pairs: list[tuple[AssetRelationship, uuid.UUID]],
    *,
    as_of: datetime | None,
    dns_freshness_window: timedelta | None,
) -> list[TraversalDecision]:
    if not pairs:
        return []
    relationships = list({relationship.id: relationship for relationship, _ in pairs}.values())
    endpoint_ids = {r.source_asset_id for r in relationships} | {r.target_asset_id for r in relationships}
    # Loaded unscoped so a cross-organization endpoint is seen -- and
    # rejected -- rather than silently looking like a missing one.
    assets = {asset.id: asset for asset in db.query(Asset).filter(Asset.id.in_(sorted(endpoint_ids, key=str)))}
    audit_entries = _creation_audit_entries(db, organization_id, [r.id for r in relationships], as_of)
    dns_evidence = _dns_resolution_evidence(db, organization_id, relationships, as_of)
    return [
        evaluate_traversal(
            relationship,
            from_asset_id=from_asset_id,
            organization_id=organization_id,
            source_asset=assets.get(relationship.source_asset_id),
            target_asset=assets.get(relationship.target_asset_id),
            audit_entry=audit_entries.get(relationship.id),
            dns_evidence=dns_evidence.get(relationship.id),
            as_of=as_of,
            dns_freshness_window=dns_freshness_window,
        )
        for relationship, from_asset_id in pairs
    ]


def _creation_audit_entries(
    db: Session, organization_id: uuid.UUID, relationship_ids: list, as_of: datetime | None = None
) -> dict[uuid.UUID, AuditLog]:
    """The earliest creation record per relationship, in this
    organization only (a re-POST of an existing relationship is logged
    again; the first entry is who originally entered it), written no
    later than `as_of` when given."""
    entries: dict[uuid.UUID, AuditLog] = {}
    query = db.query(AuditLog).filter(
        AuditLog.action == RELATIONSHIP_CREATE_AUDIT_ACTION,
        AuditLog.organization_id == organization_id,
        AuditLog.resource_id.in_(sorted(relationship_ids, key=str)),
    )
    if as_of is not None:
        query = query.filter(AuditLog.created_at <= as_of)
    # One row per relationship, collapsed in the database: repeated
    # re-POSTs of the same relationship never load their whole history.
    for row in (
        query.distinct(AuditLog.resource_id).order_by(AuditLog.resource_id, AuditLog.created_at, AuditLog.id).all()
    ):
        entries.setdefault(row.resource_id, row)
    return entries


def _dns_resolution_evidence(
    db: Session, organization_id: uuid.UUID, relationships: list[AssetRelationship], as_of: datetime | None = None
) -> dict[uuid.UUID, DnsResolutionEvidence]:
    """Per resolves_to relationship, the latest stored dns discovery
    result (no later than `as_of`, when given) recording exactly its
    direction: a completed `dns` run in this organization whose seed is
    the relationship's source, with an accepted resolves_to result whose
    asset is its target. Evidence for the reverse direction, from
    another provider, from an unfinished or failed run, or recorded
    under another organization never matches.

    DISTINCT ON keeps only the newest row per (seed, target) pair in the
    database itself, so this never loads a pair's full history. Ties go
    to the higher id -- for UUIDs Postgres' byte order and Python's
    string order agree."""
    dns_relationships = [r for r in relationships if r.relationship_type is RelationshipType.resolves_to]
    if not dns_relationships:
        return {}
    query = (
        db.query(DiscoveryResult, DiscoveryRun)
        .join(DiscoveryRun, DiscoveryRun.id == DiscoveryResult.discovery_run_id)
        .filter(
            DiscoveryRun.organization_id == organization_id,
            DiscoveryRun.provider_name == DNS_PROVIDER,
            DiscoveryRun.status == DiscoveryRunStatus.completed,
            DiscoveryRun.seed_asset_id.in_(sorted({r.source_asset_id for r in dns_relationships}, key=str)),
            DiscoveryResult.relationship_type == RelationshipType.resolves_to,
            DiscoveryResult.resulting_asset_id.in_(sorted({r.target_asset_id for r in dns_relationships}, key=str)),
            DiscoveryResult.outcome.in_(_DNS_ACCEPTED_OUTCOMES),
        )
    )
    if as_of is not None:
        query = query.filter(DiscoveryResult.created_at <= as_of)
    rows = (
        query.distinct(DiscoveryRun.seed_asset_id, DiscoveryResult.resulting_asset_id)
        .order_by(
            DiscoveryRun.seed_asset_id,
            DiscoveryResult.resulting_asset_id,
            DiscoveryResult.created_at.desc(),
            DiscoveryResult.id.desc(),
        )
        .all()
    )
    latest = {(run.seed_asset_id, result.resulting_asset_id): (result, run) for result, run in rows}

    evidence: dict[uuid.UUID, DnsResolutionEvidence] = {}
    for relationship in dns_relationships:
        match = latest.get((relationship.source_asset_id, relationship.target_asset_id))
        if match is not None:
            result, run = match
            evidence[relationship.id] = DnsResolutionEvidence(
                result_id=result.id,
                discovery_run_id=run.id,
                observed_at=result.created_at,
                record_type=(result.evidence or {}).get("record_type"),
            )
    return evidence
