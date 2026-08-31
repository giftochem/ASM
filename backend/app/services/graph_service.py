"""Read-only queries over the attack-surface graph that already exists
(Step 9.8) -- Asset/AssetRelationship/Observation, accumulated by every
provider since Step 8. This module adds no new data, no new table: it
makes the existing graph traversable, an org's recent changes visible
across assets (not just one at a time), and inventory statistics
computable, all on demand from what's already stored.
"""

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import and_, func, or_
from sqlalchemy.orm import Session

from app.core.enums import AssetType, ChangeType
from app.models.asset import Asset
from app.models.asset_relationship import AssetRelationship
from app.models.observation import Observation

MAX_GRAPH_DEPTH = 5
DEFAULT_ACTIVITY_LIMIT = 50
MAX_ACTIVITY_LIMIT = 200
_RECENT_OBSERVATION_WINDOW = timedelta(days=7)


@dataclass
class AssetGraphResult:
    nodes: list[Asset]
    edges: list[AssetRelationship]


@dataclass
class ActivityFeedEntry:
    observation: Observation
    asset_type: AssetType
    asset_value: str


def get_asset_graph(
    db: Session, organization_id: uuid.UUID, seed_asset_id: uuid.UUID, max_depth: int
) -> AssetGraphResult | None:
    """Returns None if the seed asset doesn't exist or doesn't belong to
    `organization_id` -- callers (the route) turn that into a 404,
    exactly like every other org-scoped lookup in this codebase. Callers
    must validate 0 <= max_depth <= MAX_GRAPH_DEPTH themselves before
    calling this (the route returns 400 for an invalid value without
    ever reaching here) -- this function assumes a valid depth and
    focuses purely on traversal.

    Iterative BFS, not a recursive CTE: at this codebase's stated
    per-organization scale, a handful of queries (one per depth level,
    each batched via IN()) is simpler to prove correct and test than a
    cycle-safe, bidirectional, depth-bounded recursive CTE, and no
    profiling has shown a reason to prefer the latter. Cycle safety
    comes from `visited_asset_ids`: a node already visited is never
    re-added to the frontier, so a cycle (A -> B -> C -> A) simply stops
    contributing new nodes once its members are all visited, rather
    than looping.

    Organization isolation is enforced at *every* expansion step, not
    only in the final query -- a cross-org relationship cannot exist
    today (asset_relationship_service.create_relationship refuses to
    create one), but traversal never relies on that invariant alone.

    Edges returned are the full induced subgraph over the discovered
    node set (both endpoints within max_depth hops of the seed), not
    merely the edges BFS happened to expand through -- so two sibling
    nodes that are also directly connected to each other show that
    connection too, not just their shared connection to the seed.
    """
    seed_asset = db.get(Asset, seed_asset_id)
    if seed_asset is None or seed_asset.organization_id != organization_id:
        return None

    visited_asset_ids: set[uuid.UUID] = {seed_asset.id}
    frontier: set[uuid.UUID] = {seed_asset.id}

    for _ in range(max_depth):
        if not frontier:
            break

        hop_edges = (
            db.query(AssetRelationship.source_asset_id, AssetRelationship.target_asset_id)
            .filter(
                or_(
                    AssetRelationship.source_asset_id.in_(frontier),
                    AssetRelationship.target_asset_id.in_(frontier),
                )
            )
            .all()
        )

        candidate_ids: set[uuid.UUID] = set()
        for source_id, target_id in hop_edges:
            for candidate_id in (source_id, target_id):
                if candidate_id not in visited_asset_ids:
                    candidate_ids.add(candidate_id)

        if not candidate_ids:
            break

        org_verified_ids = {
            row[0]
            for row in db.query(Asset.id)
            .filter(Asset.id.in_(candidate_ids), Asset.organization_id == organization_id)
            .all()
        }
        visited_asset_ids |= org_verified_ids
        frontier = org_verified_ids

    nodes = (
        db.query(Asset)
        .filter(Asset.id.in_(visited_asset_ids), Asset.organization_id == organization_id)
        .order_by(Asset.first_seen, Asset.id)
        .all()
    )
    edges = (
        db.query(AssetRelationship)
        .filter(
            AssetRelationship.source_asset_id.in_(visited_asset_ids),
            AssetRelationship.target_asset_id.in_(visited_asset_ids),
        )
        .order_by(AssetRelationship.first_seen, AssetRelationship.id)
        .all()
    )
    return AssetGraphResult(nodes=nodes, edges=edges)


def get_activity_feed(
    db: Session,
    organization_id: uuid.UUID,
    *,
    since: datetime | None = None,
    change_types: list[ChangeType] | None = None,
    asset_types: list[AssetType] | None = None,
    before_observed_at: datetime | None = None,
    before_id: uuid.UUID | None = None,
    limit: int = DEFAULT_ACTIVITY_LIMIT,
) -> list[ActivityFeedEntry]:
    """Organization scoping happens through Asset.organization_id --
    Observation itself carries no organization_id column (see
    app/models/observation.py), so this always joins through Asset;
    never assume otherwise.

    Ordered by (observed_at DESC, id DESC): observed_at alone is not a
    reliable tiebreaker (Postgres's now() can produce identical
    timestamps for rows written in the same transaction -- already seen
    in this codebase's own discovery-result ordering), so id is the
    deterministic secondary key.

    Pagination (Step 9.9.7) is keyset-based, not OFFSET-based: pass
    `before_observed_at`/`before_id` from the last item of the previous
    page (both together, not one alone) to fetch strictly older rows
    under the same deterministic ordering -- avoids OFFSET pagination's
    well-known drift under concurrent writes and stays efficient
    regardless of how deep a client pages.

    "Filter by discovery provider" (Step 9.9.7) has no dedicated column
    to filter on -- Observation carries no provider_name field, only
    per-provider ChangeType values (http_observed, network_changed,
    ...) that already act as a natural provider filter via
    `change_types`. No provider_name column was added for this
    (unnecessary migration for a filter `change_type` already serves).

    `limit` is capped at MAX_ACTIVITY_LIMIT even if a caller bypasses
    the route's own Query(le=MAX_ACTIVITY_LIMIT) validation and calls
    this directly -- defense in depth against an unbounded query,
    matching this codebase's established double-checking of any
    boundedness guarantee.
    """
    effective_limit = min(limit, MAX_ACTIVITY_LIMIT) if limit > 0 else DEFAULT_ACTIVITY_LIMIT

    query = (
        db.query(Observation, Asset.asset_type, Asset.value)
        .join(Asset, Observation.asset_id == Asset.id)
        .filter(Asset.organization_id == organization_id)
    )
    if since is not None:
        query = query.filter(Observation.observed_at >= since)
    if change_types:
        query = query.filter(Observation.change_type.in_(change_types))
    if asset_types:
        query = query.filter(Asset.asset_type.in_(asset_types))
    if before_observed_at is not None and before_id is not None:
        query = query.filter(
            or_(
                Observation.observed_at < before_observed_at,
                and_(Observation.observed_at == before_observed_at, Observation.id < before_id),
            )
        )

    rows = query.order_by(Observation.observed_at.desc(), Observation.id.desc()).limit(effective_limit).all()

    return [
        ActivityFeedEntry(observation=observation, asset_type=asset_type, asset_value=asset_value)
        for observation, asset_type, asset_value in rows
    ]


def get_attack_surface_summary(db: Session, organization_id: uuid.UUID) -> dict:
    """Descriptive inventory statistics only. THIS IS NOT A RISK SCORE --
    no severity is computed, no weighting is applied, connectivity is
    never treated as a proxy for risk. That's Step 14's job; this only
    counts what already exists.
    """
    total_assets = db.query(Asset).filter(Asset.organization_id == organization_id).count()

    assets_by_type = {
        asset_type.value: count
        for asset_type, count in db.query(Asset.asset_type, func.count(Asset.id))
        .filter(Asset.organization_id == organization_id)
        .group_by(Asset.asset_type)
        .all()
    }
    assets_by_status = {
        status.value: count
        for status, count in db.query(Asset.status, func.count(Asset.id))
        .filter(Asset.organization_id == organization_id)
        .group_by(Asset.status)
        .all()
    }
    assets_by_criticality = {
        criticality.value: count
        for criticality, count in db.query(Asset.criticality, func.count(Asset.id))
        .filter(Asset.organization_id == organization_id, Asset.criticality.isnot(None))
        .group_by(Asset.criticality)
        .all()
    }

    # Relationships can't cross organizations (enforced at write time in
    # asset_relationship_service.create_relationship), so joining
    # through either end gives the same, correct org-scoped count.
    relationships_by_type = {
        relationship_type.value: count
        for relationship_type, count in db.query(AssetRelationship.relationship_type, func.count(AssetRelationship.id))
        .join(Asset, AssetRelationship.source_asset_id == Asset.id)
        .filter(Asset.organization_id == organization_id)
        .group_by(AssetRelationship.relationship_type)
        .all()
    }
    total_relationships = sum(relationships_by_type.values())

    total_observations = (
        db.query(Observation)
        .join(Asset, Observation.asset_id == Asset.id)
        .filter(Asset.organization_id == organization_id)
        .count()
    )
    recent_cutoff = datetime.now(timezone.utc) - _RECENT_OBSERVATION_WINDOW
    recent_observations = (
        db.query(Observation)
        .join(Asset, Observation.asset_id == Asset.id)
        .filter(Asset.organization_id == organization_id, Observation.observed_at >= recent_cutoff)
        .count()
    )

    isolated_asset_count = (
        db.query(Asset)
        .filter(
            Asset.organization_id == organization_id,
            ~Asset.id.in_(db.query(AssetRelationship.source_asset_id)),
            ~Asset.id.in_(db.query(AssetRelationship.target_asset_id)),
        )
        .count()
    )

    return {
        "total_assets": total_assets,
        "assets_by_type": assets_by_type,
        "assets_by_status": assets_by_status,
        "assets_by_criticality": assets_by_criticality,
        "total_relationships": total_relationships,
        "relationships_by_type": relationships_by_type,
        "total_observations": total_observations,
        "recent_observations_last_7_days": recent_observations,
        "isolated_asset_count": isolated_asset_count,
    }
