"""Explainable, on-demand asset prioritization (Step 9.10) -- answers
"what should the analyst investigate first?" using only intelligence
already collected by Steps 8-9.9 (Asset/AssetRelationship/Observation).
No active network request is ever made here; no score is persisted.

DELIBERATELY SEPARATE from app.services.risk_engine: that module scores
*scan Findings* (a numeric, weighted 0-100 formula over
severity/exposure/exploitability, producing a RiskSeverityBand).
Prioritization here scores *assets*, from *discovery/graph context*
(exposure, business criticality, change recency, graph connectivity,
evidence confidence) -- a genuinely different input and question.
Reusing risk_engine's vocabulary (RiskSeverityBand) or scoring shape
here would conflate two independent signal sources; a future step may
deliberately unify them, but that's not decided here, so this stays its
own named concept (PriorityLevel, not RiskSeverityBand).

NOT A SCORE: this is a small, ordered, human-readable set of rules, not
a weighted numeric formula -- every branch corresponds directly to a
reason returned in the response. Missing data (no criticality, no
environment) is never treated as "low importance": it lowers the
reported CONFIDENCE in the result, never silently substitutes a default
value into the priority decision itself.
"""

import enum
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.core.enums import (
    AssetCriticality,
    AssetEnvironment,
    AssetType,
    ChangeType,
    LifecycleStatus,
)
from app.models.asset import Asset
from app.models.asset_relationship import AssetRelationship
from app.models.certificate import Certificate
from app.models.observation import Observation
from app.services.discovery_normalization_service import canonicalize_for_comparison


class PriorityLevel(str, enum.Enum):
    """The single, user-facing category -- deliberately a small, named
    set matching the spec's own suggested vocabulary, kept distinct
    from RiskSeverityBand (see module docstring)."""

    informational = "informational"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


_PRIORITY_ORDER = {
    PriorityLevel.critical: 4,
    PriorityLevel.high: 3,
    PriorityLevel.medium: 2,
    PriorityLevel.low: 1,
    PriorityLevel.informational: 0,
}

# "Recent" for change-recency purposes. A plain module constant, not a
# Settings field -- matches graph_service.MAX_GRAPH_DEPTH's precedent
# for an internal, documented threshold that isn't an operator-facing
# control.
RECENT_CHANGE_WINDOW = timedelta(hours=24)

# Internet-facing-by-nature asset types -- the ones whose whole purpose
# is to be reachable from outside the organization. asn/cloud_resource
# describe infrastructure CONTEXT, not a reachable endpoint in their own
# right; api/repository/service/tls_certificate are ambiguous with the
# current data model and are deliberately treated as unknown exposure
# rather than guessed. Public (not prefixed with `_`) since Step 9.12's
# alert_service reuses this exact set for its own exposure-type check --
# a second, private copy would risk drifting from this one.
INHERENTLY_EXPOSED_TYPES = {AssetType.domain, AssetType.subdomain, AssetType.url, AssetType.ip_address, AssetType.http_endpoint}

_HTTP_CHANGE_TYPES = (ChangeType.http_observed, ChangeType.http_changed)
_NETWORK_CHANGE_TYPES = (ChangeType.network_observed, ChangeType.network_changed)
_INFRASTRUCTURE_CHANGE_TYPES = (ChangeType.infrastructure_observed, ChangeType.infrastructure_changed)
_CERTIFICATE_CHANGE_TYPES = (ChangeType.certificate_observed, ChangeType.certificate_changed)
_DNS_EVIDENCE_TYPES = (ChangeType.dns_records_observed,)

# Every change_type this service ever looks at -- fetched in one batched
# query per prioritize_assets() call, never per-asset.
_RELEVANT_CHANGE_TYPES = (
    ChangeType.asset_status_changed,
    *_HTTP_CHANGE_TYPES,
    *_NETWORK_CHANGE_TYPES,
    *_INFRASTRUCTURE_CHANGE_TYPES,
    *_CERTIFICATE_CHANGE_TYPES,
    *_DNS_EVIDENCE_TYPES,
)


@dataclass
class PriorityReason:
    signal: str
    impact: str  # "low" | "medium" | "high"
    description: str
    evidence: dict | None = None


@dataclass
class PriorityDimensions:
    exposure: str  # "none" | "low" | "moderate" | "high"
    business_criticality: str  # "unknown" | "low" | "medium" | "high" | "critical"
    change_recency: str  # "none" | "low" | "moderate" | "high"
    connectivity_relevance: str  # "none" | "low" | "moderate" | "high"
    evidence_confidence: str  # "low" | "medium" | "high"


@dataclass
class AssetPriorityResult:
    asset: Asset
    priority: PriorityLevel
    confidence_label: str  # "low" | "medium" | "high"
    confidence_value: float  # the underlying minimum numeric confidence, never hidden
    dimensions: PriorityDimensions
    reasons: list[PriorityReason] = field(default_factory=list)
    evaluated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


def _latest_by_type(observations: list[Observation], change_types: tuple) -> Observation | None:
    """observations is assumed pre-sorted newest-first (the batched
    query in prioritize_assets orders by observed_at desc)."""
    for obs in observations:
        if obs.change_type in change_types:
            return obs
    return None


def _is_recent(observed_at: datetime, now: datetime) -> bool:
    return (now - observed_at) <= RECENT_CHANGE_WINDOW


def _compute_exposure(
    asset: Asset, observations: list[Observation], has_certificate: bool
) -> tuple[str, list[PriorityReason]]:
    reasons: list[PriorityReason] = []
    http_obs = _latest_by_type(observations, _HTTP_CHANGE_TYPES)
    dns_obs = _latest_by_type(observations, _DNS_EVIDENCE_TYPES)

    http_reachable = False
    if http_obs is not None and http_obs.current_value:
        try:
            data = json.loads(http_obs.current_value)
            http_reachable = data.get("status_code") is not None
        except (ValueError, TypeError):
            pass

    if http_reachable:
        reasons.append(PriorityReason(
            signal="http_exposed", impact="high",
            description="Asset responds to HTTP/HTTPS requests", evidence={"observed_at": http_obs.observed_at.isoformat()},
        ))
    if has_certificate:
        reasons.append(PriorityReason(
            signal="tls_exposed", impact="medium",
            description="Asset presents a TLS certificate",
        ))
    if dns_obs is not None:
        reasons.append(PriorityReason(
            signal="dns_present", impact="low",
            description="Asset has observed DNS records",
        ))
    if asset.asset_type is AssetType.ip_address:
        reasons.append(PriorityReason(
            signal="publicly_routable_ip", impact="medium",
            description="Asset is a publicly routable IP address",
        ))

    inherently_exposed = asset.asset_type in INHERENTLY_EXPOSED_TYPES

    if http_reachable and (has_certificate or asset.asset_type is AssetType.ip_address):
        level = "high"
    elif http_reachable or (inherently_exposed and (has_certificate or dns_obs is not None)):
        level = "moderate"
    elif inherently_exposed:
        level = "low"
    else:
        level = "none"

    return level, reasons


def _compute_business_criticality(asset: Asset) -> tuple[str, list[PriorityReason], bool]:
    """Returns (level, reasons, context_known) -- context_known is False
    when BOTH criticality and environment are unset, feeding into the
    overall confidence downgrade (Step 9.10.4: never pretend unknown
    context means "normal").
    """
    reasons: list[PriorityReason] = []
    context_known = False

    if asset.criticality is not None:
        context_known = True
        impact = "high" if asset.criticality in (AssetCriticality.high, AssetCriticality.critical) else "medium"
        reasons.append(PriorityReason(
            signal="asset_criticality", impact=impact,
            description=f"Asset criticality is explicitly set to '{asset.criticality.value}'",
        ))
        level = asset.criticality.value
    else:
        level = "unknown"

    if asset.environment is not None:
        context_known = True
        if asset.environment == AssetEnvironment.production:
            reasons.append(PriorityReason(
                signal="production_environment", impact="high",
                description="Asset is tagged as a production environment asset",
            ))
            if level == "unknown":
                level = "medium"  # production alone, with no explicit criticality, still deserves attention
        else:
            reasons.append(PriorityReason(
                signal="non_production_environment", impact="low",
                description=f"Asset is tagged as '{asset.environment.value}', not production",
            ))

    return level, reasons, context_known


def _compute_change_recency(
    asset: Asset, observations: list[Observation], now: datetime
) -> tuple[str, list[PriorityReason]]:
    reasons: list[PriorityReason] = []
    strong_change = False
    any_change = False

    if asset.status == LifecycleStatus.first_seen and _is_recent(asset.first_seen, now):
        reasons.append(PriorityReason(
            signal="newly_discovered", impact="medium",
            description=f"Asset was first discovered within the last {int(RECENT_CHANGE_WINDOW.total_seconds() // 3600)} hours",
            evidence={"first_seen": asset.first_seen.isoformat()},
        ))
        any_change = True

    if asset.status == LifecycleStatus.disappeared:
        reasons.append(PriorityReason(
            signal="disappeared", impact="low",
            description="Asset is currently marked disappeared (not recently reconfirmed)",
        ))

    status_obs = _latest_by_type(observations, (ChangeType.asset_status_changed,))
    if status_obs is not None and _is_recent(status_obs.observed_at, now):
        try:
            prev = json.loads(status_obs.previous_value or "{}").get("status")
            curr = json.loads(status_obs.current_value or "{}").get("status")
        except (ValueError, TypeError):
            prev = curr = None
        if curr == "active" and prev in ("stale", "disappeared"):
            reasons.append(PriorityReason(
                signal="recently_revived", impact="medium",
                description="Asset was recently revived from stale/disappeared back to active",
                evidence={"observed_at": status_obs.observed_at.isoformat()},
            ))
            strong_change = True
            any_change = True

    for label, change_types, description in (
        ("certificate_changed", _CERTIFICATE_CHANGE_TYPES, "TLS certificate changed recently"),
        ("http_changed", _HTTP_CHANGE_TYPES, "HTTP behavior changed recently"),
        ("infrastructure_changed", _INFRASTRUCTURE_CHANGE_TYPES, "Cloud/infrastructure classification changed recently"),
        ("network_changed", _NETWORK_CHANGE_TYPES, "Network/ASN attribution changed recently"),
    ):
        obs = _latest_by_type(observations, change_types)
        if obs is not None and obs.change_type.value.endswith("_changed") and _is_recent(obs.observed_at, now):
            reasons.append(PriorityReason(
                signal=label, impact="high", description=description,
                evidence={"observed_at": obs.observed_at.isoformat()},
            ))
            strong_change = True
            any_change = True

    dns_change = _dns_change_recent(observations, now)
    if dns_change:
        reasons.append(PriorityReason(
            signal="dns_changed", impact="medium",
            description="DNS evidence differs from the previous observation, observed recently",
        ))
        strong_change = True
        any_change = True

    if strong_change:
        level = "high"
    elif any_change:
        level = "moderate"
    else:
        level = "none"

    return level, reasons


def _dns_change_recent(observations: list[Observation], now: datetime) -> bool:
    """dns_records_observed has no _changed counterpart (Step 9.2's
    record_seed_evidence never did comparison-based dedup -- disclosed,
    unchanged behavior, not something this service alters). Detecting a
    genuine DNS change means comparing the two most recent
    dns_records_observed rows here, read-only, using the same
    canonicalization already trusted for this exact purpose elsewhere.
    """
    dns_observations = [o for o in observations if o.change_type in _DNS_EVIDENCE_TYPES]
    if len(dns_observations) < 2:
        return False
    newest, second_newest = dns_observations[0], dns_observations[1]
    if not _is_recent(newest.observed_at, now):
        return False
    try:
        newest_value = canonicalize_for_comparison(json.loads(newest.current_value or "{}"))
        previous_value = canonicalize_for_comparison(json.loads(second_newest.current_value or "{}"))
    except (ValueError, TypeError):
        return False
    return newest_value != previous_value


def _compute_connectivity_relevance(
    asset: Asset, relationships: list[AssetRelationship], neighbor_criticalities: dict
) -> tuple[str, list[PriorityReason]]:
    reasons: list[PriorityReason] = []
    active_relationships = [r for r in relationships if r.status != LifecycleStatus.disappeared]
    neighbor_ids = {
        (r.target_asset_id if r.source_asset_id == asset.id else r.source_asset_id) for r in active_relationships
    }
    relationship_count = len(active_relationships)
    relationship_types = sorted({r.relationship_type.value for r in active_relationships})

    if relationship_count == 0:
        reasons.append(PriorityReason(
            signal="isolated_asset", impact="low",
            description="Asset has no active relationships to any other asset",
        ))
        return "none", reasons

    connects_to_critical = any(
        neighbor_criticalities.get(nid) in (AssetCriticality.high, AssetCriticality.critical) for nid in neighbor_ids
    )

    reasons.append(PriorityReason(
        signal="connectivity", impact="medium" if relationship_count < 5 else "high",
        description=f"Asset has {relationship_count} active relationship(s) ({', '.join(relationship_types)})",
        evidence={"relationship_count": relationship_count, "relationship_types": relationship_types},
    ))

    if connects_to_critical:
        reasons.append(PriorityReason(
            signal="connects_to_critical_asset", impact="high",
            description="Asset is connected to at least one high/critical-criticality asset -- potential attack-surface relevance, not a proven exploit path",
        ))
        return "high", reasons

    if relationship_count >= 5:
        level = "moderate"
    else:
        level = "low"
    return level, reasons


def _compute_evidence_confidence(
    asset: Asset, contributing_observations: list[Observation], context_known: bool
) -> tuple[str, float]:
    numeric_values = [asset.confidence] + [obs.confidence for obs in contributing_observations]
    minimum = min(numeric_values) if numeric_values else asset.confidence

    if minimum >= 0.85:
        label = "high"
    elif minimum >= 0.6:
        label = "medium"
    else:
        label = "low"

    if not context_known:
        # Missing business context (criticality AND environment both
        # unset) means the priority decision leaned entirely on
        # exposure/change/connectivity signals -- honestly reflected as
        # reduced confidence, never silently treated as "normal."
        label = {"high": "medium", "medium": "low", "low": "low"}[label]

    return label, minimum


def _derive_overall_priority(
    exposure: str, business_criticality: str, change_recency: str, connectivity: str, asset_status: LifecycleStatus
) -> PriorityLevel:
    """Small, ordered, human-readable rules -- not a weighted formula.
    Each branch below maps directly onto the reasons already collected
    by the dimension functions above.
    """
    if asset_status == LifecycleStatus.disappeared:
        # A disappeared asset isn't currently exposed, regardless of
        # what it used to be -- informational at most, never higher.
        return PriorityLevel.informational

    is_exposed = exposure in ("moderate", "high")
    high_business_value = business_criticality in ("high", "critical")
    has_strong_change = change_recency == "high"
    has_any_change = change_recency in ("moderate", "high")
    strong_connectivity = connectivity == "high"

    if is_exposed and high_business_value and has_strong_change:
        return PriorityLevel.critical
    if is_exposed and (high_business_value or has_strong_change or strong_connectivity):
        return PriorityLevel.high
    if is_exposed or has_any_change or connectivity == "moderate":
        return PriorityLevel.medium
    if exposure == "low" or connectivity == "low":
        return PriorityLevel.low
    return PriorityLevel.informational


def _evaluate_one(
    asset: Asset,
    observations: list[Observation],
    relationships: list[AssetRelationship],
    neighbor_criticalities: dict,
    has_certificate: bool,
    now: datetime,
) -> AssetPriorityResult:
    exposure_level, exposure_reasons = _compute_exposure(asset, observations, has_certificate)
    criticality_level, criticality_reasons, context_known = _compute_business_criticality(asset)
    change_level, change_reasons = _compute_change_recency(asset, observations, now)
    connectivity_level, connectivity_reasons = _compute_connectivity_relevance(asset, relationships, neighbor_criticalities)

    priority = _derive_overall_priority(exposure_level, criticality_level, change_level, connectivity_level, asset.status)

    contributing_observations = [
        obs for obs in observations
        if obs.change_type in _RELEVANT_CHANGE_TYPES and _is_recent(obs.observed_at, now)
    ]
    confidence_label, confidence_value = _compute_evidence_confidence(asset, contributing_observations, context_known)

    all_reasons = exposure_reasons + criticality_reasons + change_reasons + connectivity_reasons
    if not context_known:
        all_reasons.append(PriorityReason(
            signal="unknown_business_context", impact="low",
            description="Neither criticality nor environment is set for this asset -- business context is unknown, not assumed low",
        ))

    return AssetPriorityResult(
        asset=asset,
        priority=priority,
        confidence_label=confidence_label,
        confidence_value=confidence_value,
        dimensions=PriorityDimensions(
            exposure=exposure_level,
            business_criticality=criticality_level,
            change_recency=change_level,
            connectivity_relevance=connectivity_level,
            evidence_confidence=confidence_label,
        ),
        reasons=all_reasons,
        evaluated_at=now,
    )


def prioritize_assets(
    db: Session,
    organization_id: uuid.UUID,
    *,
    asset_ids: list[uuid.UUID] | None = None,
    asset_types: list[AssetType] | None = None,
    environments: list[AssetEnvironment] | None = None,
    criticalities: list[AssetCriticality] | None = None,
    priority_levels: list[PriorityLevel] | None = None,
    limit: int = 50,
) -> list[AssetPriorityResult]:
    """The batched entry point -- computes priority for every matching
    asset in a bounded, fixed number of queries (never one query per
    asset): one for the asset list, one for all their relevant
    Observations, one for all their relationships, one for neighbor
    criticalities, one for certificate presence. Priority itself is
    never persisted -- recomputed fresh on every call from current data.

    Sorted by priority (critical first), then asset value ascending as
    a deterministic tiebreaker -- identical input always produces
    identical output and ordering.

    `asset_ids`, if given, restricts evaluation to exactly that set --
    added for Step 9.12's alert_service, which needs batched priority
    for a specific handful of assets a discovery run touched, not every
    asset in the organization. Reuses this function's existing batching
    entirely rather than a second, parallel implementation (get_asset_priority,
    the single-asset variant, is what alert_service used to call once
    per touched asset -- a real N+1, caught by a dedicated query-count
    test, that this parameter fixes).
    """
    query = db.query(Asset).filter(Asset.organization_id == organization_id)
    if asset_ids is not None:
        query = query.filter(Asset.id.in_(asset_ids))
    if asset_types:
        query = query.filter(Asset.asset_type.in_(asset_types))
    if environments:
        query = query.filter(Asset.environment.in_(environments))
    if criticalities:
        query = query.filter(Asset.criticality.in_(criticalities))
    assets = query.order_by(Asset.value).all()
    if not assets:
        return []

    asset_ids = [a.id for a in assets]
    asset_id_set = set(asset_ids)
    now = datetime.now(timezone.utc)

    observations = (
        db.query(Observation)
        .filter(Observation.asset_id.in_(asset_ids), Observation.change_type.in_(_RELEVANT_CHANGE_TYPES))
        .order_by(Observation.observed_at.desc(), Observation.id.desc())
        .all()
    )
    observations_by_asset: dict = {aid: [] for aid in asset_ids}
    for obs in observations:
        observations_by_asset.setdefault(obs.asset_id, []).append(obs)

    relationships = (
        db.query(AssetRelationship)
        .filter(or_(AssetRelationship.source_asset_id.in_(asset_ids), AssetRelationship.target_asset_id.in_(asset_ids)))
        .all()
    )
    relationships_by_asset: dict = {aid: [] for aid in asset_ids}
    neighbor_ids: set = set()
    for rel in relationships:
        if rel.source_asset_id in asset_id_set:
            relationships_by_asset[rel.source_asset_id].append(rel)
            if rel.target_asset_id not in asset_id_set:
                neighbor_ids.add(rel.target_asset_id)
        if rel.target_asset_id in asset_id_set:
            relationships_by_asset[rel.target_asset_id].append(rel)
            if rel.source_asset_id not in asset_id_set:
                neighbor_ids.add(rel.source_asset_id)

    neighbor_criticalities: dict = {a.id: a.criticality for a in assets}  # in-batch assets already loaded
    if neighbor_ids:
        for other_id, other_criticality in db.query(Asset.id, Asset.criticality).filter(Asset.id.in_(neighbor_ids)).all():
            neighbor_criticalities[other_id] = other_criticality

    certificate_asset_ids = {
        row[0] for row in db.query(Certificate.asset_id).filter(Certificate.asset_id.in_(asset_ids)).distinct().all()
    }

    results = [
        _evaluate_one(
            asset,
            observations_by_asset.get(asset.id, []),
            relationships_by_asset.get(asset.id, []),
            neighbor_criticalities,
            asset.id in certificate_asset_ids,
            now,
        )
        for asset in assets
    ]

    if priority_levels:
        allowed = set(priority_levels)
        results = [r for r in results if r.priority in allowed]

    results.sort(key=lambda r: (-_PRIORITY_ORDER[r.priority], r.asset.value))

    return results[:limit]


def get_asset_priority(db: Session, organization_id: uuid.UUID, asset_id: uuid.UUID) -> AssetPriorityResult | None:
    """Single-asset variant -- reuses prioritize_assets' exact logic
    (via a single-asset-scoped query) rather than a second
    implementation, so the two endpoints can never disagree."""
    asset = db.get(Asset, asset_id)
    if asset is None or asset.organization_id != organization_id:
        return None

    now = datetime.now(timezone.utc)
    observations = (
        db.query(Observation)
        .filter(Observation.asset_id == asset.id, Observation.change_type.in_(_RELEVANT_CHANGE_TYPES))
        .order_by(Observation.observed_at.desc(), Observation.id.desc())
        .all()
    )
    relationships = (
        db.query(AssetRelationship)
        .filter(or_(AssetRelationship.source_asset_id == asset.id, AssetRelationship.target_asset_id == asset.id))
        .all()
    )
    neighbor_ids = {
        (r.target_asset_id if r.source_asset_id == asset.id else r.source_asset_id) for r in relationships
    }
    neighbor_criticalities = {asset.id: asset.criticality}
    if neighbor_ids:
        for other_id, other_criticality in db.query(Asset.id, Asset.criticality).filter(Asset.id.in_(neighbor_ids)).all():
            neighbor_criticalities[other_id] = other_criticality

    has_certificate = db.query(Certificate).filter(Certificate.asset_id == asset.id).first() is not None

    return _evaluate_one(asset, observations, relationships, neighbor_criticalities, has_certificate, now)
