"""Exposure Path Engine (Stage B) -- bounded, deterministic, read-only.

Finds observed exposure paths: sequences of distinct assets
    entry point -> ... -> target
where the entry point has current, attributable service-exposure
evidence at the assessment time (exposure_evidence_service), the target
is an asset explicitly marked `high` or `critical`, and every step is a
relationship the traversal rules allow forward at that time
(relationship_traversal_rules, with DNS evidence no older than the
freshness window). A zero-hop path is a target that is itself an
observed entry point.

These are OBSERVED EXPOSURE PATHS, NOT VERIFIED EXPLOIT CHAINS:
exploitability, privilege escalation and lateral movement are never
assessed. A DNS step shows that one name resolves to another name or
address -- not that compromise can propagate between them -- so a path
made only of DNS steps is reported as an observed infrastructure
association. Analyst-entered steps are reported as assertions.

Search: backward from the targets, one batched level per hop (the same
per-level batching graph_service.get_asset_graph uses). Each level loads
the relationships pointing INTO the current frontier and evaluates every
one forward, from its own source, so a path can only ever use a
relationship in its permitted direction; nothing is reversed or invented.
Searching from the bounded target set means exposure is assessed only
for the assets actually reached, never for a whole organization.

Every limit is applied while searching, and hitting one stops cleanly
and is reported as a truncation -- a truncated result never claims to be
exhaustive. Ordering is total (criticality, hop count, target, then the
path's assets and relationships), so the same data, assessment time and
limits always give the same paths.
"""

import enum
import uuid
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import case
from sqlalchemy.orm import Session

from app.core.enums import AssetCriticality, LifecycleStatus
from app.models.asset import Asset
from app.models.asset_relationship import AssetRelationship
from app.services import exposure_evidence_service, relationship_traversal_rules
from app.services.exposure_evidence_service import EvidenceType, ExposureEvidence
from app.services.relationship_traversal_rules import RelationshipProvenance, TraversalDecision

DISCLAIMER = "Observed exposure paths; exploitability not assessed."
NOT_ASSESSED = "Exploitability, privilege escalation and lateral movement have not been assessed."

# Request-adjustable limits: each is both the default and the maximum.
MAX_HOPS = 3
MAX_TARGETS = 25
MAX_PATHS = 100
MAX_NODES = 500

# Internal safety valves (not request parameters), reported as
# truncations when hit: relationships fetched and evaluated per request,
# and partial paths built while enumerating.
MAX_RELATIONSHIPS = 2_000
MAX_PATH_EXPANSIONS = 10_000

# One window for both entry-point evidence and DNS steps.
FRESHNESS_WINDOW = exposure_evidence_service.FRESHNESS_WINDOW

TARGET_CRITICALITIES = (AssetCriticality.critical, AssetCriticality.high)


class StepBasis(str, enum.Enum):
    observed_dns_association = "observed_dns_association"
    analyst_asserted = "analyst_asserted"


class PathBasis(str, enum.Enum):
    direct_exposure = "direct_exposure"  # zero-hop
    observed_dns_association = "observed_dns_association"
    analyst_asserted = "analyst_asserted"
    observed_dns_and_analyst_asserted = "observed_dns_and_analyst_asserted"


# Every allowed traversal rule must map to a basis; a rule without one is
# never followed (fail closed if the rule set grows).
_RULE_BASIS = {
    "dns_resolution_forward": StepBasis.observed_dns_association,
    "analyst_entered_forward": StepBasis.analyst_asserted,
}

_EVIDENCE_LABELS = {
    EvidenceType.http_response: "HTTP response",
    EvidenceType.tls_handshake: "TLS handshake",
    EvidenceType.open_port: "open port",
}


@dataclass(frozen=True)
class PathLimits:
    max_hops: int = MAX_HOPS
    max_targets: int = MAX_TARGETS
    max_paths: int = MAX_PATHS
    max_nodes: int = MAX_NODES


def validate_limits(
    max_hops: int = MAX_HOPS, max_targets: int = MAX_TARGETS, max_paths: int = MAX_PATHS, max_nodes: int = MAX_NODES
) -> PathLimits:
    """Raises ValueError naming every out-of-range limit."""
    checks = (
        ("max_hops", max_hops, 0, MAX_HOPS),
        ("max_targets", max_targets, 1, MAX_TARGETS),
        ("max_paths", max_paths, 1, MAX_PATHS),
        ("max_nodes", max_nodes, 1, MAX_NODES),
    )
    errors = [f"{name} must be between {low} and {high}" for name, value, low, high in checks if not low <= value <= high]
    if errors:
        raise ValueError("; ".join(errors))
    return PathLimits(max_hops=max_hops, max_targets=max_targets, max_paths=max_paths, max_nodes=max_nodes)


def resolve_assessment_time(as_of: datetime | None, now: datetime) -> datetime:
    """The explicit assessment time, or `now`. Raises ValueError for a
    time without a timezone or in the future -- evidence can't be
    assessed at a time that hasn't happened."""
    if as_of is None:
        return now
    if as_of.tzinfo is None or as_of.utcoffset() is None:
        raise ValueError("as_of must include a timezone offset, e.g. 2026-10-19T12:00:00Z")
    if as_of > now:
        raise ValueError("as_of cannot be in the future")
    return as_of.astimezone(timezone.utc)


@dataclass(frozen=True)
class PathAsset:
    asset_id: uuid.UUID
    asset_type: str
    value: str
    criticality: str | None
    environment: str | None


@dataclass(frozen=True)
class PathStep:
    relationship_id: uuid.UUID
    relationship_type: str
    from_asset_id: uuid.UUID
    to_asset_id: uuid.UUID
    direction: str  # always "forward"
    basis: StepBasis
    rule: str
    reason: str
    provenance: RelationshipProvenance


@dataclass(frozen=True)
class ExposurePath:
    entry_point: PathAsset
    target: PathAsset
    nodes: tuple[PathAsset, ...]
    steps: tuple[PathStep, ...]
    basis: PathBasis
    entry_evidence: tuple[ExposureEvidence, ...]  # the entry point's qualifying evidence
    interpretation: str
    limitations: tuple[str, ...]

    @property
    def hop_count(self) -> int:
        return len(self.steps)

    @property
    def is_zero_hop(self) -> bool:
        return not self.steps


@dataclass(frozen=True)
class Truncation:
    limit: str  # max_targets | max_nodes | max_paths | relationship_budget | expansion_budget | evidence_budget
    detail: str


@dataclass(frozen=True)
class ExposurePathResult:
    organization_id: uuid.UUID
    assessed_at: datetime
    limits: PathLimits
    freshness_window: timedelta
    paths: tuple[ExposurePath, ...]
    eligible_target_count: int  # active assets marked high/critical in the organization
    examined_target_count: int
    examined_node_count: int  # distinct assets the search admitted, targets included
    evaluated_relationship_count: int
    entry_point_count: int  # observed entry points among the examined assets
    truncations: tuple[Truncation, ...]
    limitations: tuple[str, ...]

    @property
    def truncated(self) -> bool:
        return bool(self.truncations)


_RESULT_LIMITATIONS = (
    "Only assets explicitly marked high or critical are targets; unclassified assets are never treated as targets.",
    "Evidence is evaluated as of the assessment time, but lifecycle status, criticality and relationships are the "
    "current stored values, not reconstructed for that time.",
    "Exposure evidence shows an entry point was observed responding within the freshness window, not that it is "
    "reachable now.",
)


def find_exposure_paths(
    db: Session, organization_id: uuid.UUID, *, as_of: datetime, limits: PathLimits | None = None
) -> ExposurePathResult:
    """Read-only: never writes, never triggers discovery or scanning, never
    touches the network. A fixed number of queries per hop level."""
    limits = limits or PathLimits()
    validate_limits(limits.max_hops, limits.max_targets, limits.max_paths, limits.max_nodes)
    truncations: dict[str, Truncation] = {}

    def truncate(limit: str, detail: str) -> None:
        truncations.setdefault(limit, Truncation(limit, detail))

    targets, eligible_count = _select_targets(db, organization_id, limits, truncate)
    examined: dict[uuid.UUID, Asset] = {target.id: target for target in targets}
    in_edges, evaluated = _search_backward(db, organization_id, targets, examined, as_of, limits, truncate)

    exposure = exposure_evidence_service.assess_exposure(
        db, organization_id, sorted(examined, key=str), as_of=as_of, freshness_window=FRESHNESS_WINDOW
    )
    entry_points = {asset_id for asset_id, assessed in exposure.items() if assessed.is_observed_entry_point}
    incomplete = sum(1 for assessed in exposure.values() if assessed.evidence_truncated)
    if incomplete:
        truncate(
            "evidence_budget",
            f"the evidence budget ({exposure_evidence_service.EVIDENCE_ROW_BUDGET} rows) was reached: {incomplete} "
            f"examined assets' evidence wasn't fully examined, so they may be missing entry-point evidence (nothing "
            f"that couldn't be fully checked was treated as current)",
        )

    paths = _enumerate_paths(targets, examined, in_edges, entry_points, exposure, limits, truncate)
    return ExposurePathResult(
        organization_id=organization_id,
        assessed_at=as_of,
        limits=limits,
        freshness_window=FRESHNESS_WINDOW,
        paths=tuple(paths),
        eligible_target_count=eligible_count,
        examined_target_count=len(targets),
        examined_node_count=len(examined),
        evaluated_relationship_count=evaluated,
        entry_point_count=len(entry_points),
        truncations=tuple(truncations.values()),
        limitations=_RESULT_LIMITATIONS,
    )


# --- search -------------------------------------------------------------------------


def _select_targets(db: Session, organization_id, limits: PathLimits, truncate) -> tuple[list[Asset], int]:
    eligible = db.query(Asset).filter(
        Asset.organization_id == organization_id,
        Asset.criticality.in_(TARGET_CRITICALITIES),
        Asset.is_active.is_(True),
        Asset.status != LifecycleStatus.disappeared,
    )
    eligible_count = eligible.count()
    critical_first = case((Asset.criticality == AssetCriticality.critical, 0), else_=1)
    targets = eligible.order_by(critical_first, Asset.value, Asset.id).limit(limits.max_targets).all()
    if eligible_count > len(targets):
        truncate(
            "max_targets",
            f"{eligible_count} active assets are marked high or critical; only the first {len(targets)} "
            f"(critical first, then by value and id) were examined",
        )
    if len(targets) > limits.max_nodes:
        truncate("max_nodes", f"the node limit ({limits.max_nodes}) is below the number of targets selected")
        targets = targets[: limits.max_nodes]
    return targets, eligible_count


def _search_backward(db: Session, organization_id, targets, examined, as_of, limits: PathLimits, truncate):
    """Level-by-level search from the targets toward possible entry
    points. Returns the allowed edges into each examined asset and how
    many relationships were evaluated."""
    in_edges: dict[uuid.UUID, list[tuple[uuid.UUID, TraversalDecision]]] = defaultdict(list)
    frontier = [target.id for target in targets]
    evaluated = 0
    for _ in range(limits.max_hops):
        if not frontier:
            break
        stop = False
        budget = MAX_RELATIONSHIPS - evaluated
        incoming = (
            db.query(AssetRelationship)
            .filter(AssetRelationship.target_asset_id.in_(sorted(frontier, key=str)))
            .order_by(
                AssetRelationship.target_asset_id,
                AssetRelationship.source_asset_id,
                AssetRelationship.relationship_type,
                AssetRelationship.id,
            )
            .limit(budget + 1)
            .all()
        )
        if len(incoming) > budget:
            incoming = incoming[:budget]
            stop = True
            truncate(
                "relationship_budget",
                f"more than {MAX_RELATIONSHIPS} relationships lead into the examined assets; the rest were not evaluated",
            )
        evaluated += len(incoming)

        decisions = relationship_traversal_rules.evaluate_forward_traversals(
            db, organization_id, incoming, as_of=as_of, dns_freshness_window=FRESHNESS_WINDOW
        )
        allowed = [d for d in decisions if d.allowed and d.direction == "forward" and d.rule in _RULE_BASIS]

        new_ids = sorted({d.from_asset_id for d in allowed} - examined.keys(), key=str)
        new_assets = (
            db.query(Asset).filter(Asset.id.in_(new_ids), Asset.organization_id == organization_id).all() if new_ids else []
        )
        new_assets.sort(key=lambda asset: (asset.value, str(asset.id)))
        room = limits.max_nodes - len(examined)
        if len(new_assets) > room:
            truncate(
                "max_nodes",
                f"the search reached more than {limits.max_nodes} assets; assets beyond the limit (by value and id) "
                f"were not examined",
            )
            new_assets = new_assets[:room]
            stop = True
        for asset in new_assets:
            examined[asset.id] = asset
        for decision in allowed:
            if decision.from_asset_id in examined:
                in_edges[decision.to_asset_id].append((decision.from_asset_id, decision))

        frontier = [asset.id for asset in new_assets]
        if stop:
            break

    for edges in in_edges.values():
        edges.sort(key=lambda edge: (examined[edge[0]].value, str(edge[0]), edge[1].relationship_type, str(edge[1].relationship_id)))
    return in_edges, evaluated


def _enumerate_paths(targets, examined, in_edges, entry_points, exposure, limits: PathLimits, truncate) -> list[ExposurePath]:
    """Simple paths only (no asset repeats, so cycles can't loop), emitted
    in the total order: criticality group, hop count, target, then the
    path's own assets and relationships. Stopping at a limit therefore
    always returns a prefix of that order."""
    paths: list[ExposurePath] = []
    expansions = 0
    for criticality in TARGET_CRITICALITIES:
        group = [target for target in targets if target.criticality is criticality]
        partial = {target.id: [((target.id,), ())] for target in group}
        for hops in range(limits.max_hops + 1):
            for target in group:
                complete = [path for path in partial[target.id] if path[0][0] in entry_points]
                complete.sort(key=lambda path: _path_key(path, examined))
                for nodes, decisions in complete:
                    if len(paths) >= limits.max_paths:
                        truncate("max_paths", f"more than {limits.max_paths} paths were found; only the first {limits.max_paths} are returned")
                        return paths
                    paths.append(_build_path(nodes, decisions, examined, exposure))
            if hops == limits.max_hops:
                break
            for target in group:
                extended = []
                for nodes, decisions in partial[target.id]:
                    for predecessor, decision in in_edges.get(nodes[0], ()):
                        if predecessor in nodes:
                            continue
                        expansions += 1
                        if expansions > MAX_PATH_EXPANSIONS:
                            truncate(
                                "expansion_budget",
                                f"path enumeration stopped after {MAX_PATH_EXPANSIONS} partial paths; longer paths "
                                f"were not enumerated",
                            )
                            return paths
                        extended.append(((predecessor,) + nodes, (decision,) + decisions))
                partial[target.id] = extended
    return paths


def _path_key(path, examined):
    nodes, decisions = path
    return tuple((examined[node].value, str(node)) for node in nodes) + tuple(str(d.relationship_id) for d in decisions)


# --- results ------------------------------------------------------------------------


def _snapshot(asset: Asset) -> PathAsset:
    return PathAsset(
        asset_id=asset.id,
        asset_type=asset.asset_type.value,
        value=asset.value,
        criticality=asset.criticality.value if asset.criticality is not None else None,
        environment=asset.environment.value if asset.environment is not None else None,
    )


def _build_path(nodes, decisions, examined, exposure) -> ExposurePath:
    assets = tuple(_snapshot(examined[node]) for node in nodes)
    steps = tuple(
        PathStep(
            relationship_id=d.relationship_id,
            relationship_type=d.relationship_type,
            from_asset_id=d.from_asset_id,
            to_asset_id=d.to_asset_id,
            direction=d.direction,
            basis=_RULE_BASIS[d.rule],
            rule=d.rule,
            reason=d.reason,
            provenance=d.provenance,
        )
        for d in decisions
    )
    entry, target = assets[0], assets[-1]
    evidence = tuple(e for e in exposure[entry.asset_id].evidence if e.qualifies)
    bases = {step.basis for step in steps}
    if not steps:
        basis = PathBasis.direct_exposure
    elif bases == {StepBasis.observed_dns_association}:
        basis = PathBasis.observed_dns_association
    elif bases == {StepBasis.analyst_asserted}:
        basis = PathBasis.analyst_asserted
    else:
        basis = PathBasis.observed_dns_and_analyst_asserted

    kinds = ", ".join(sorted({_EVIDENCE_LABELS[e.evidence_type] for e in evidence}))
    exposed = f"{entry.value} has current observed service exposure ({kinds})"
    marked = f"{target.value} (marked {target.criticality})"
    if basis is PathBasis.direct_exposure:
        interpretation = f"Observed exposure: {exposed} and is itself marked {target.criticality}."
    elif basis is PathBasis.observed_dns_association:
        interpretation = (
            f"Observed infrastructure association: {exposed} and is associated with {marked} only through DNS "
            f"resolution records. DNS resolution shows that one name points at another name or address; it does not "
            f"show that compromise of one can propagate to the other."
        )
    elif basis is PathBasis.analyst_asserted:
        interpretation = (
            f"Analyst-asserted path: {exposed} and is linked to {marked} through relationships an analyst entered "
            f"(recorded in the audit log); the links are assertions, not observations."
        )
    else:
        interpretation = (
            f"Mixed path: {exposed} and is linked to {marked} through observed DNS resolution records and "
            f"analyst-asserted relationships. Neither shows that compromise can propagate along the path."
        )
    interpretation = f"{interpretation} {NOT_ASSESSED}"

    limitations = [NOT_ASSESSED]
    if StepBasis.observed_dns_association in bases:
        limitations.append(
            "DNS resolution records show name-to-address association only; they do not prove that compromise can "
            "propagate between assets."
        )
    if StepBasis.analyst_asserted in bases:
        limitations.append(
            "Includes analyst-asserted relationships: entered by an analyst and recorded in the audit log, not "
            "independently observed."
        )
    if any(e.inconclusive_attempts for e in evidence):
        limitations.append("Some entry-point evidence has later inconclusive attempts; see that evidence's limitations.")
    return ExposurePath(
        entry_point=entry,
        target=target,
        nodes=assets,
        steps=steps,
        basis=basis,
        entry_evidence=evidence,
        interpretation=interpretation,
        limitations=tuple(limitations),
    )
