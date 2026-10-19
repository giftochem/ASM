import json
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import and_, or_
from sqlalchemy.orm import Session

from app.core.client_ip import get_client_ip
from app.core.enums import (
    AssetCriticality,
    AssetEnvironment,
    AssetSource,
    AssetType,
    ChangeType,
    LifecycleStatus,
    UserRole,
)
from app.database import get_db
from app.dependencies import get_current_user, require_role
from app.models.asset import Asset
from app.models.asset_relationship import AssetRelationship
from app.models.observation import Observation
from app.models.user import User
from app.schemas.asset import (
    AssetAuthorizationConfirm,
    AssetAuthorizationRevoke,
    AssetCreate,
    AssetRead,
    AssetRelationshipCreate,
    AssetRelationshipRead,
    AssetUpdate,
    ObservationRead,
)
from app.schemas.graph import (
    ActivityFeedItem,
    AssetGraphResponse,
    AttackSurfaceSummary,
    GraphEdge,
    GraphNode,
    GraphTraversalMetadata,
    SharedInfrastructureGroup,
)
from app.schemas.exposure_path import (
    AnalystAssertionRef,
    DnsEvidenceRef,
    EntryEvidenceRef,
    ExposurePathLimits,
    ExposurePathRead,
    ExposurePathsResponse,
    PathAssetRef,
    PathStepRead,
    PathTruncation,
)
from app.schemas.risk import AssetPriority, PriorityDimensions, PriorityReason
from app.services import (
    asset_relationship_service,
    attack_path_service,
    audit_service,
    discovery_normalization_service,
    graph_service,
    observation_service,
    prioritization_service,
)
from app.services.prioritization_service import PriorityLevel

router = APIRouter(prefix="/assets", tags=["assets"])


def _get_org_asset_or_404(db: Session, asset_id: uuid.UUID, organization_id: uuid.UUID) -> Asset:
    asset = db.get(Asset, asset_id)
    if asset is None or asset.organization_id != organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")
    return asset


# Step 9.13: MAX_ASSET_LIST_LIMIT only applies when a caller actually
# passes `limit` -- see list_assets below. Matches the cap every other
# paginated endpoint in this codebase already uses (alerts, activity,
# findings), so a caller opting into pagination gets the same bound
# everywhere.
MAX_ASSET_LIST_LIMIT = 200


@router.get("", response_model=list[AssetRead])
def list_assets(
    asset_type: list[AssetType] | None = Query(default=None),
    status_filter: list[LifecycleStatus] | None = Query(default=None, alias="status"),
    environment: list[AssetEnvironment] | None = Query(default=None),
    criticality: list[AssetCriticality] | None = Query(default=None),
    search: str | None = Query(default=None, max_length=255),
    after_value: str | None = Query(default=None),
    after_id: uuid.UUID | None = Query(default=None),
    limit: int | None = Query(default=None, ge=1, le=MAX_ASSET_LIST_LIMIT),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[Asset]:
    """Step 9.13: optional server-side filtering + keyset pagination,
    added on top of the original Step 8 endpoint -- every parameter is
    optional and additive. `limit` deliberately has NO default: when
    omitted, this returns the full org-scoped list exactly like it
    always has (every existing caller -- the pre-9.13 AssetsPage, and
    ~20 backend tests -- relies on that unbounded behavior and is
    unaffected). Pagination only activates when a caller explicitly
    opts in by passing `limit`.

    Ordered by (value ASC, id ASC) -- deterministic, matching this
    codebase's established convention (see e.g.
    prioritization_service.prioritize_assets) -- previously this
    endpoint had no ORDER BY at all. `after_value`+`after_id` (both
    together, taken from the last item of the previous page) page
    forward through that same ordering -- keyset, not OFFSET, for the
    same drift-under-concurrent-writes reason every other paginated
    endpoint here already chose it.
    """
    query = db.query(Asset).filter(Asset.organization_id == current_user.organization_id)
    if asset_type:
        query = query.filter(Asset.asset_type.in_(asset_type))
    if status_filter:
        query = query.filter(Asset.status.in_(status_filter))
    if environment:
        query = query.filter(Asset.environment.in_(environment))
    if criticality:
        query = query.filter(Asset.criticality.in_(criticality))
    if search:
        query = query.filter(Asset.value.ilike(f"%{search}%"))
    if after_value is not None and after_id is not None:
        query = query.filter(
            or_(
                Asset.value > after_value,
                and_(Asset.value == after_value, Asset.id > after_id),
            )
        )

    query = query.order_by(Asset.value, Asset.id)
    if limit is not None:
        query = query.limit(limit)
    return query.all()


# --- Step 9.8: organization-level graph/intelligence queries ---------------
# These three routes use static path segments ("activity"/"summary"/
# "shared-infrastructure") one level under /assets, the exact same shape
# as GET /{asset_id} -- they MUST be registered before that route below,
# or FastAPI/Starlette's registration-order route matching would try to
# parse e.g. "activity" as a UUID asset_id and 422 before ever reaching
# these handlers. Read-only, no role restriction, matching every other
# read endpoint in this router (GET /assets, GET /{id}/relationships,
# GET /{id}/observations are all unrestricted-by-role today).


@router.get("/activity", response_model=list[ActivityFeedItem])
def get_activity_feed(
    since: datetime | None = None,
    change_type: list[ChangeType] | None = Query(default=None),
    asset_type: list[AssetType] | None = Query(default=None),
    before_observed_at: datetime | None = None,
    before_id: uuid.UUID | None = None,
    limit: int = Query(default=graph_service.DEFAULT_ACTIVITY_LIMIT, ge=1, le=graph_service.MAX_ACTIVITY_LIMIT),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[ActivityFeedItem]:
    """Organization-wide, chronological feed of Observations across every
    asset -- the cross-asset counterpart to GET /{asset_id}/observations,
    which only ever showed one asset's history at a time. This IS the
    Step 9.9.7 "GET /assets/changes" endpoint -- not duplicated under a
    second name, since post-Step-9.9.4 (meaningless duplicate
    observations no longer written) this endpoint's behavior and a
    hypothetical separate "/changes" endpoint would be functionally
    identical; see the Step 9.9 README section for the full reasoning.

    `before_observed_at`/`before_id` together page backward through the
    feed (keyset pagination) -- pass both from the last item of the
    previous page to fetch strictly older rows.
    """
    entries = graph_service.get_activity_feed(
        db,
        current_user.organization_id,
        since=since,
        change_types=change_type,
        asset_types=asset_type,
        before_observed_at=before_observed_at,
        before_id=before_id,
        limit=limit,
    )
    return [
        ActivityFeedItem(
            id=entry.observation.id,
            asset_id=entry.observation.asset_id,
            asset_type=entry.asset_type,
            asset_value=entry.asset_value,
            change_type=entry.observation.change_type,
            field_name=entry.observation.field_name,
            previous_value=entry.observation.previous_value,
            current_value=entry.observation.current_value,
            observed_at=entry.observation.observed_at,
            source=entry.observation.source,
            confidence=entry.observation.confidence,
        )
        for entry in entries
    ]


@router.get("/summary", response_model=AttackSurfaceSummary)
def get_attack_surface_summary(
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> AttackSurfaceSummary:
    """Descriptive inventory statistics only -- explicitly not a risk
    score. See graph_service.get_attack_surface_summary's docstring.
    """
    return AttackSurfaceSummary(**graph_service.get_attack_surface_summary(db, current_user.organization_id))


@router.get("/shared-infrastructure", response_model=list[SharedInfrastructureGroup])
def get_shared_infrastructure(
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> list[dict]:
    """Thin wrapper over the existing Step 9.7 grouping function --
    the classification/grouping logic itself is untouched and already
    exhaustively tested in test_cloud_discovery_integration.py.
    """
    return discovery_normalization_service.get_shared_infrastructure_groups(db, current_user.organization_id)


def _to_asset_priority(result: prioritization_service.AssetPriorityResult) -> AssetPriority:
    return AssetPriority(
        asset_id=result.asset.id,
        asset_type=result.asset.asset_type,
        asset_value=result.asset.value,
        priority=result.priority,
        confidence_label=result.confidence_label,
        confidence_value=result.confidence_value,
        dimensions=PriorityDimensions(
            exposure=result.dimensions.exposure,
            business_criticality=result.dimensions.business_criticality,
            change_recency=result.dimensions.change_recency,
            connectivity_relevance=result.dimensions.connectivity_relevance,
            evidence_confidence=result.dimensions.evidence_confidence,
        ),
        reasons=[
            PriorityReason(signal=r.signal, impact=r.impact, description=r.description, evidence=r.evidence)
            for r in result.reasons
        ],
        evaluated_at=result.evaluated_at,
    )


@router.get("/prioritized", response_model=list[AssetPriority])
def get_prioritized_assets(
    asset_type: list[AssetType] | None = Query(default=None),
    environment: list[AssetEnvironment] | None = Query(default=None),
    criticality: list[AssetCriticality] | None = Query(default=None),
    priority: list[PriorityLevel] | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[AssetPriority]:
    """Explainable, on-demand asset prioritization (Step 9.10) -- "what
    should the analyst investigate first?" Computed fresh from existing
    discovery/graph data on every call, never persisted, never causing
    any active network request. See prioritization_service's module
    docstring for the full model. Ordering is deterministic: priority
    (critical first), then asset value ascending.
    """
    results = prioritization_service.prioritize_assets(
        db,
        current_user.organization_id,
        asset_types=asset_type,
        environments=environment,
        criticalities=criticality,
        priority_levels=priority,
        limit=limit,
    )
    return [_to_asset_priority(r) for r in results]


def _path_asset_ref(asset: attack_path_service.PathAsset) -> PathAssetRef:
    return PathAssetRef(
        asset_id=asset.asset_id,
        asset_type=asset.asset_type,
        value=asset.value,
        criticality=asset.criticality,
        environment=asset.environment,
    )


def _path_step_read(step: attack_path_service.PathStep) -> PathStepRead:
    provenance = step.provenance
    dns = provenance.dns_evidence
    return PathStepRead(
        relationship_id=step.relationship_id,
        relationship_type=step.relationship_type,
        from_asset_id=step.from_asset_id,
        to_asset_id=step.to_asset_id,
        direction=step.direction,
        basis=step.basis,
        relationship_source=provenance.source,
        rule=step.rule,
        reason=step.reason,
        dns_evidence=(
            DnsEvidenceRef(
                result_id=dns.result_id,
                discovery_run_id=dns.discovery_run_id,
                observed_at=dns.observed_at,
                record_type=dns.record_type,
                freshness="current",
            )
            if step.basis is attack_path_service.StepBasis.observed_dns_association and dns is not None
            else None
        ),
        analyst_assertion=(
            AnalystAssertionRef(audit_log_id=provenance.audit_log_id, asserted_at=provenance.entered_at)
            if step.basis is attack_path_service.StepBasis.analyst_asserted and provenance.audit_log_id is not None
            else None
        ),
    )


def _to_exposure_paths_response(result: attack_path_service.ExposurePathResult) -> ExposurePathsResponse:
    return ExposurePathsResponse(
        disclaimer=attack_path_service.DISCLAIMER,
        organization_id=result.organization_id,
        assessed_at=result.assessed_at,
        freshness_window_seconds=int(result.freshness_window.total_seconds()),
        limits=ExposurePathLimits(
            max_hops=result.limits.max_hops,
            max_targets=result.limits.max_targets,
            max_paths=result.limits.max_paths,
            max_nodes=result.limits.max_nodes,
        ),
        path_count=len(result.paths),
        eligible_target_count=result.eligible_target_count,
        examined_target_count=result.examined_target_count,
        examined_node_count=result.examined_node_count,
        evaluated_relationship_count=result.evaluated_relationship_count,
        entry_point_count=result.entry_point_count,
        truncated=result.truncated,
        truncation_reasons=[PathTruncation(limit=t.limit, detail=t.detail) for t in result.truncations],
        limitations=list(result.limitations),
        paths=[
            ExposurePathRead(
                entry_point=_path_asset_ref(path.entry_point),
                target=_path_asset_ref(path.target),
                hop_count=path.hop_count,
                is_zero_hop=path.is_zero_hop,
                basis=path.basis,
                nodes=[_path_asset_ref(node) for node in path.nodes],
                steps=[_path_step_read(step) for step in path.steps],
                entry_evidence=[
                    EntryEvidenceRef(
                        evidence_type=e.evidence_type.value,
                        source=e.source,
                        subject=e.subject,
                        freshness=e.freshness.value,
                        first_confirmed_at=e.first_confirmed_at,
                        last_confirmed_at=e.last_confirmed_at,
                        latest_attempt_at=e.latest_attempt_at,
                        inconclusive_attempts=e.inconclusive_attempts,
                        latest_inconclusive_at=e.latest_inconclusive_at,
                        discovery_run_id=e.discovery_run_id,
                        scan_id=e.scan_id,
                        result_id=e.result_id,
                        observation_id=e.observation_id,
                        limitations=list(e.limitations),
                    )
                    for e in path.entry_evidence
                ],
                interpretation=path.interpretation,
                limitations=list(path.limitations),
            )
            for path in result.paths
        ],
    )


# Static, so registered before /{asset_id} below (see the note on the
# other static routes above).
@router.get("/exposure-paths", response_model=ExposurePathsResponse)
def get_exposure_paths(
    as_of: datetime | None = None,
    max_hops: int = attack_path_service.MAX_HOPS,
    max_targets: int = attack_path_service.MAX_TARGETS,
    max_paths: int = attack_path_service.MAX_PATHS,
    max_nodes: int = attack_path_service.MAX_NODES,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ExposurePathsResponse:
    """Stage B: observed exposure paths from assets with current
    service-exposure evidence to assets explicitly marked high or
    critical -- observed exposure, NOT verified exploit chains. See
    attack_path_service for the model. Read-only for every role: it
    never writes, never triggers discovery or scanning, and never
    touches the network.

    Limits follow GET /{asset_id}/graph's traversal-bound convention: a
    well-formed value outside its range is a 400 naming the range; a
    malformed value (not an integer, not a datetime) is FastAPI's own
    422. `as_of` defaults to now; it must carry a timezone and can't be
    in the future (400).
    """
    try:
        limits = attack_path_service.validate_limits(max_hops, max_targets, max_paths, max_nodes)
        assessed_at = attack_path_service.resolve_assessment_time(as_of, datetime.now(timezone.utc))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    result = attack_path_service.find_exposure_paths(
        db, current_user.organization_id, as_of=assessed_at, limits=limits
    )
    return _to_exposure_paths_response(result)


@router.get("/{asset_id}", response_model=AssetRead)
def get_asset(
    asset_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Asset:
    return _get_org_asset_or_404(db, asset_id, current_user.organization_id)


def _enum_value(value) -> str | None:
    return value.value if value is not None else None


# PATCH on the path-param route can't shadow the static GET routes above
# (/activity, /summary, /shared-infrastructure, /prioritized): a different
# method never matches them, and PATCH on one of those names is a 422
# (not a UUID), not a call to some other handler.
@router.patch("/{asset_id}", response_model=AssetRead)
def update_asset(
    asset_id: uuid.UUID,
    payload: AssetUpdate,
    request: Request,
    current_user: User = Depends(require_role(UserRole.admin, UserRole.analyst)),
    db: Session = Depends(get_db),
) -> Asset:
    """Stage A.1: human-set business context only (criticality,
    environment) -- see AssetUpdate for what's deliberately not updatable.

    The row is locked (SELECT ... FOR UPDATE) within the caller's
    organization, so concurrent updates serialize and each one's recorded
    before-values are exactly what it replaced; a cross-organization id is
    a 404, like every other org-scoped lookup. The field change, its
    asset_updated Observation (the same field_name="asset_state" JSON shape
    discovery's own asset refreshes use) and its audit entry are committed
    together or not at all. An update that changes nothing writes nothing.
    Priority is computed on demand from the stored values, so it reflects
    the change on the next read with no extra step.
    """
    asset = (
        db.query(Asset)
        .filter(Asset.id == asset_id, Asset.organization_id == current_user.organization_id)
        .with_for_update()
        .populate_existing()
        .one_or_none()
    )
    if asset is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")

    requested = {field: getattr(payload, field) for field in payload.model_fields_set}
    before = {field: _enum_value(getattr(asset, field)) for field in requested}
    after = {field: _enum_value(value) for field, value in requested.items()}
    changed = sorted(field for field in requested if before[field] != after[field])

    try:
        if changed:
            for field in changed:
                setattr(asset, field, requested[field])
            observation_service.record_observation(
                db,
                asset,
                ChangeType.asset_updated,
                field_name="asset_state",
                previous_value=json.dumps({field: before[field] for field in changed}),
                current_value=json.dumps({field: after[field] for field in changed}),
                source=AssetSource.manual,
            )
            audit_service.log_action(
                db,
                user_id=current_user.id,
                organization_id=current_user.organization_id,
                action="asset.update",
                resource_type="asset",
                resource_id=asset.id,
                details={"changes": {field: {"from": before[field], "to": after[field]} for field in changed}},
                ip_address=get_client_ip(request),
            )
        db.commit()  # also releases the row lock when nothing changed
    except Exception:
        db.rollback()
        raise
    db.refresh(asset)
    return asset


@router.post("", response_model=AssetRead, status_code=status.HTTP_201_CREATED)
def create_asset(
    payload: AssetCreate,
    request: Request,
    current_user: User = Depends(require_role(UserRole.admin, UserRole.analyst)),
    db: Session = Depends(get_db),
) -> Asset:
    existing = (
        db.query(Asset)
        .filter(
            Asset.organization_id == current_user.organization_id,
            Asset.asset_type == payload.asset_type,
            Asset.value == payload.value,
        )
        .first()
    )
    if existing is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Asset already exists")

    asset = Asset(
        organization_id=current_user.organization_id,
        asset_type=payload.asset_type,
        value=payload.value,
        notes=payload.notes,
    )
    db.add(asset)
    db.flush()

    observation_service.record_observation(
        db,
        asset,
        ChangeType.asset_created,
        current_value=asset.value,
    )
    audit_service.log_action(
        db,
        user_id=current_user.id,
        organization_id=current_user.organization_id,
        action="asset.create",
        resource_type="asset",
        resource_id=asset.id,
        details={"asset_type": asset.asset_type.value, "value": asset.value},
        ip_address=get_client_ip(request),
    )
    db.commit()
    db.refresh(asset)
    return asset


@router.post("/{asset_id}/revoke-authorization", response_model=AssetRead)
def revoke_authorization(
    asset_id: uuid.UUID,
    payload: AssetAuthorizationRevoke,
    request: Request,
    current_user: User = Depends(require_role(UserRole.admin, UserRole.analyst)),
    db: Session = Depends(get_db),
) -> Asset:
    """The other half of the guardrail's write path. A scan already queued
    at the moment of revocation is not retroactively stopped by this call
    alone — app.services.scan_executor re-checks authorization immediately
    before running any module and fails closed if it's been revoked, which
    is what actually makes revocation effective against in-flight scans.
    """
    asset = _get_org_asset_or_404(db, asset_id, current_user.organization_id)
    asset.authorization_confirmed = False
    asset.authorization_confirmed_by = None
    asset.authorization_confirmed_at = None

    audit_service.log_action(
        db,
        user_id=current_user.id,
        organization_id=current_user.organization_id,
        action="asset.revoke_authorization",
        resource_type="asset",
        resource_id=asset.id,
        details={"reason": payload.reason},
        ip_address=get_client_ip(request),
    )
    db.commit()
    db.refresh(asset)
    return asset


@router.post("/{asset_id}/confirm-authorization", response_model=AssetRead)
def confirm_authorization(
    asset_id: uuid.UUID,
    payload: AssetAuthorizationConfirm,
    request: Request,
    current_user: User = Depends(require_role(UserRole.admin, UserRole.analyst)),
    db: Session = Depends(get_db),
) -> Asset:
    """The guardrail's write path: an asset cannot be scanned until this
    has been called with authorization_confirmed=true. See the scope/
    authorization disclaimer in README.md before confirming any target.
    """
    if not payload.authorization_confirmed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="authorization_confirmed must be true to confirm authorization",
        )

    asset = _get_org_asset_or_404(db, asset_id, current_user.organization_id)
    asset.authorization_confirmed = True
    asset.authorization_confirmed_by = current_user.id
    asset.authorization_confirmed_at = datetime.now(timezone.utc)

    audit_service.log_action(
        db,
        user_id=current_user.id,
        organization_id=current_user.organization_id,
        action="asset.confirm_authorization",
        resource_type="asset",
        resource_id=asset.id,
        details={"attestation_note": payload.attestation_note},
        ip_address=get_client_ip(request),
    )
    db.commit()
    db.refresh(asset)
    return asset


def _get_org_relationship_or_404(
    db: Session, asset_id: uuid.UUID, relationship_id: uuid.UUID, organization_id: uuid.UUID
) -> AssetRelationship:
    relationship = db.get(AssetRelationship, relationship_id)
    if (
        relationship is None
        or relationship.source_asset_id != asset_id
        or relationship.source_asset.organization_id != organization_id
    ):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Relationship not found")
    return relationship


@router.post(
    "/{asset_id}/relationships",
    response_model=AssetRelationshipRead,
    status_code=status.HTTP_201_CREATED,
)
def create_relationship(
    asset_id: uuid.UUID,
    payload: AssetRelationshipCreate,
    request: Request,
    current_user: User = Depends(require_role(UserRole.admin, UserRole.analyst)),
    db: Session = Depends(get_db),
) -> AssetRelationship:
    """Creates (or refreshes, if one already exists — see
    asset_relationship_service.create_relationship) a relationship from
    this asset to `target_asset_id`. Both assets are resolved via the
    same org-scoped lookup used everywhere else in this router, so a
    cross-org target 404s exactly like any other cross-org asset lookup.
    """
    source_asset = _get_org_asset_or_404(db, asset_id, current_user.organization_id)
    target_asset = _get_org_asset_or_404(db, payload.target_asset_id, current_user.organization_id)

    if source_asset.id == target_asset.id:
        # Caught here so this is a clean 400, not a raw 500 from the DB's
        # ck_relationship_no_self_reference CHECK constraint -- that
        # constraint stays as the actual defense-in-depth guarantee (it
        # protects any future caller that bypasses this route), this is
        # just a better-shaped error for the common case.
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="An asset cannot have a relationship to itself"
        )

    relationship = asset_relationship_service.create_relationship(
        db,
        source_asset=source_asset,
        target_asset=target_asset,
        relationship_type=payload.relationship_type,
        confidence=payload.confidence,
        notes=payload.notes,
    )

    audit_service.log_action(
        db,
        user_id=current_user.id,
        organization_id=current_user.organization_id,
        action="asset.relationship.create",
        resource_type="asset_relationship",
        resource_id=relationship.id,
        details={
            "source_asset_id": str(source_asset.id),
            "target_asset_id": str(target_asset.id),
            "relationship_type": payload.relationship_type.value,
        },
        ip_address=get_client_ip(request),
    )
    db.commit()
    db.refresh(relationship)
    return relationship


@router.get("/{asset_id}/relationships", response_model=list[AssetRelationshipRead])
def list_relationships(
    asset_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[AssetRelationship]:
    """Both directions — an asset can be the source or the target of a
    relationship, and callers generally want the whole neighborhood, not
    just outgoing edges.
    """
    asset = _get_org_asset_or_404(db, asset_id, current_user.organization_id)
    return (
        db.query(AssetRelationship)
        .filter(or_(AssetRelationship.source_asset_id == asset.id, AssetRelationship.target_asset_id == asset.id))
        .all()
    )


@router.post("/{asset_id}/relationships/{relationship_id}/mark-disappeared", response_model=AssetRelationshipRead)
def mark_relationship_disappeared(
    asset_id: uuid.UUID,
    relationship_id: uuid.UUID,
    request: Request,
    current_user: User = Depends(require_role(UserRole.admin, UserRole.analyst)),
    db: Session = Depends(get_db),
) -> AssetRelationship:
    """Soft-remove: sets status=disappeared rather than deleting the row,
    matching the confirm/revoke-authorization convention of a dedicated
    action endpoint for a meaningful state transition.
    """
    relationship = _get_org_relationship_or_404(db, asset_id, relationship_id, current_user.organization_id)
    relationship = asset_relationship_service.mark_relationship_disappeared(db, relationship)

    audit_service.log_action(
        db,
        user_id=current_user.id,
        organization_id=current_user.organization_id,
        action="asset.relationship.mark_disappeared",
        resource_type="asset_relationship",
        resource_id=relationship.id,
        ip_address=get_client_ip(request),
    )
    db.commit()
    db.refresh(relationship)
    return relationship


@router.get("/{asset_id}/observations", response_model=list[ObservationRead])
def list_observations(
    asset_id: uuid.UUID,
    limit: int = 50,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[Observation]:
    asset = _get_org_asset_or_404(db, asset_id, current_user.organization_id)
    return (
        db.query(Observation)
        .filter(Observation.asset_id == asset.id)
        .order_by(Observation.observed_at.desc())
        .limit(limit)
        .all()
    )


@router.get("/{asset_id}/graph", response_model=AssetGraphResponse)
def get_asset_graph(
    asset_id: uuid.UUID,
    depth: int = 1,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> AssetGraphResponse:
    """N-hop neighborhood of one asset (nodes + the full induced-subgraph
    edges among them) -- read-only, bounded by MAX_GRAPH_DEPTH.

    depth is validated here, not via FastAPI's declarative Query(ge=,
    le=) constraints: those return 422 on violation, but an invalid or
    over-limit depth here must be a 400 specifically (explicit
    requirement) -- so it's checked manually instead.
    """
    if depth < 0 or depth > graph_service.MAX_GRAPH_DEPTH:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"depth must be between 0 and {graph_service.MAX_GRAPH_DEPTH}",
        )

    # Confirms the seed exists and belongs to this org (404 otherwise),
    # reusing the same helper every other asset-scoped route uses.
    _get_org_asset_or_404(db, asset_id, current_user.organization_id)

    result = graph_service.get_asset_graph(db, current_user.organization_id, asset_id, depth)
    # result is never None here: the lookup above already confirmed the
    # seed exists and belongs to this org.

    return AssetGraphResponse(
        nodes=[GraphNode.model_validate(node) for node in result.nodes],
        edges=[GraphEdge.model_validate(edge) for edge in result.edges],
        metadata=GraphTraversalMetadata(
            seed_asset_id=asset_id, depth=depth, node_count=len(result.nodes), edge_count=len(result.edges)
        ),
    )


@router.get("/{asset_id}/risk", response_model=AssetPriority)
def get_asset_risk(
    asset_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> AssetPriority:
    """Single-asset explainable priority (Step 9.10) -- the per-asset
    counterpart to GET /assets/prioritized, sharing the exact same
    underlying evaluation logic so the two endpoints can never disagree.
    """
    _get_org_asset_or_404(db, asset_id, current_user.organization_id)
    result = prioritization_service.get_asset_priority(db, current_user.organization_id, asset_id)
    # result is never None here: the lookup above already confirmed the
    # asset exists and belongs to this org.
    return _to_asset_priority(result)
