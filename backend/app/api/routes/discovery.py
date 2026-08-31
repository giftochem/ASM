import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session, joinedload

from app.config import settings
from app.core.enums import UserRole
from app.core.exceptions import AuthorizationNotConfirmedError
from app.database import get_db
from app.dependencies import get_current_user, require_role
from app.discovery.registry import DISCOVERY_PROVIDER_REGISTRY
from app.models.asset import Asset
from app.models.discovery_result import DiscoveryResult
from app.models.discovery_run import DiscoveryRun
from app.models.discovery_schedule import DiscoverySchedule
from app.models.user import User
from app.schemas.discovery import DiscoveryProviderInfo, DiscoveryResultRead, DiscoveryRunCreate, DiscoveryRunRead
from app.schemas.discovery_schedule import DiscoveryScheduleCreate, DiscoveryScheduleRead, DiscoveryScheduleUpdate
from app.services import discovery_schedule_service, discovery_scheduler_executor, discovery_service
from app.services.rate_limit import limiter

router = APIRouter(prefix="/discovery", tags=["discovery"])


@router.get("/providers", response_model=list[DiscoveryProviderInfo])
def list_providers(current_user: User = Depends(get_current_user)) -> list[DiscoveryProviderInfo]:
    """Step 9.13: read-only catalog of registered providers -- for the
    schedule-creation form to know valid provider_name values and which
    asset types each supports, without hand-mirroring the registry
    frontend-side. No role restriction, matching every other read
    endpoint in this router; `current_user` is required only for
    authentication, not used otherwise (this data is identical across
    every organization).
    """
    return [
        DiscoveryProviderInfo(
            name=provider.name,
            applicable_seed_types=sorted(provider.applicable_seed_types, key=lambda t: t.value),
            depends_on=sorted(provider.depends_on),
        )
        for provider in sorted(DISCOVERY_PROVIDER_REGISTRY.values(), key=lambda p: p.name)
    ]


def _get_org_run_or_404(db: Session, run_id: uuid.UUID, organization_id: uuid.UUID) -> DiscoveryRun:
    run = db.get(DiscoveryRun, run_id)
    if run is None or run.organization_id != organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Discovery run not found")
    return run


@router.get("/runs", response_model=list[DiscoveryRunRead])
def list_runs(
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> list[DiscoveryRun]:
    return (
        db.query(DiscoveryRun)
        .filter(DiscoveryRun.organization_id == current_user.organization_id)
        .order_by(DiscoveryRun.created_at.desc())
        .all()
    )


@router.get("/runs/{run_id}", response_model=DiscoveryRunRead)
def get_run(
    run_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> DiscoveryRun:
    return _get_org_run_or_404(db, run_id, current_user.organization_id)


@router.get("/runs/{run_id}/results", response_model=list[DiscoveryResultRead])
def list_run_results(
    run_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[DiscoveryResult]:
    run = _get_org_run_or_404(db, run_id, current_user.organization_id)
    return (
        db.query(DiscoveryResult)
        .filter(DiscoveryResult.discovery_run_id == run.id)
        .order_by(DiscoveryResult.created_at)
        .all()
    )


@router.post("/runs", response_model=DiscoveryRunRead, status_code=status.HTTP_201_CREATED)
@limiter.limit(settings.rate_limit_discovery_create)
def create_run(
    payload: DiscoveryRunCreate,
    request: Request,
    current_user: User = Depends(require_role(UserRole.admin, UserRole.analyst)),
    db: Session = Depends(get_db),
) -> DiscoveryRun:
    """Same authorization contract as POST /scans: the seed asset must
    already have authorization_confirmed=true (403 otherwise). Runs
    synchronously in this pass -- see discovery_service for why.
    """
    seed_asset = db.get(Asset, payload.seed_asset_id)
    if seed_asset is None or seed_asset.organization_id != current_user.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")

    try:
        provider = discovery_service.validate_discovery_request(seed_asset, payload.provider_name)
    except AuthorizationNotConfirmedError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    run = discovery_service.create_run(db, seed_asset, payload.provider_name, current_user)
    return discovery_service.execute_run(db, run, provider, seed_asset)


# --- Step 9.11: recurring discovery schedules -------------------------------


def _get_org_schedule_or_404(db: Session, schedule_id: uuid.UUID, organization_id: uuid.UUID) -> DiscoverySchedule:
    schedule = db.get(DiscoverySchedule, schedule_id)
    if schedule is None or schedule.organization_id != organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Discovery schedule not found")
    return schedule


@router.get("/schedules", response_model=list[DiscoveryScheduleRead])
def list_schedules(
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> list[DiscoverySchedule]:
    # joinedload: Step 9.13's DiscoveryScheduleRead.seed_asset_value/
    # seed_asset_type/last_run_status read these relationships per row --
    # eager-loading here keeps that two JOINs instead of up to 2N
    # lazy-loads across the list.
    return (
        db.query(DiscoverySchedule)
        .options(joinedload(DiscoverySchedule.seed_asset), joinedload(DiscoverySchedule.last_run))
        .filter(DiscoverySchedule.organization_id == current_user.organization_id)
        .order_by(DiscoverySchedule.created_at.desc())
        .all()
    )


@router.get("/schedules/{schedule_id}", response_model=DiscoveryScheduleRead)
def get_schedule(
    schedule_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> DiscoverySchedule:
    return _get_org_schedule_or_404(db, schedule_id, current_user.organization_id)


@router.post("/schedules", response_model=DiscoveryScheduleRead, status_code=status.HTTP_201_CREATED)
@limiter.limit(settings.rate_limit_discovery_create)
def create_schedule(
    payload: DiscoveryScheduleCreate,
    request: Request,
    current_user: User = Depends(require_role(UserRole.admin, UserRole.analyst)),
    db: Session = Depends(get_db),
) -> DiscoverySchedule:
    """Same authorization contract as POST /discovery/runs: the seed
    asset must already have authorization_confirmed=true (403
    otherwise). That check is re-verified live, every time, immediately
    before each actual scheduled execution -- this creation-time check
    only rejects an obviously-doomed schedule early; it is never trusted
    as a one-time gate (see discovery_scheduler_executor's module
    docstring for the full reasoning).
    """
    seed_asset = db.get(Asset, payload.seed_asset_id)
    if seed_asset is None or seed_asset.organization_id != current_user.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")

    try:
        discovery_schedule_service.validate_schedule_request(seed_asset, payload.provider_name, payload.interval_hours)
    except AuthorizationNotConfirmedError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    return discovery_schedule_service.create_schedule(
        db, seed_asset, payload.provider_name, payload.interval_hours, current_user
    )


@router.patch("/schedules/{schedule_id}", response_model=DiscoveryScheduleRead)
def update_schedule(
    schedule_id: uuid.UUID,
    payload: DiscoveryScheduleUpdate,
    current_user: User = Depends(require_role(UserRole.admin, UserRole.analyst)),
    db: Session = Depends(get_db),
) -> DiscoverySchedule:
    schedule = _get_org_schedule_or_404(db, schedule_id, current_user.organization_id)
    try:
        return discovery_schedule_service.update_schedule(
            db, schedule, enabled=payload.enabled, interval_hours=payload.interval_hours
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.delete("/schedules/{schedule_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_schedule(
    schedule_id: uuid.UUID,
    current_user: User = Depends(require_role(UserRole.admin, UserRole.analyst)),
    db: Session = Depends(get_db),
) -> None:
    schedule = _get_org_schedule_or_404(db, schedule_id, current_user.organization_id)
    discovery_schedule_service.delete_schedule(db, schedule)


@router.post("/schedules/{schedule_id}/run", response_model=DiscoveryRunRead, status_code=status.HTTP_202_ACCEPTED)
@limiter.limit(settings.rate_limit_discovery_create)
def trigger_schedule(
    schedule_id: uuid.UUID,
    request: Request,
    current_user: User = Depends(require_role(UserRole.admin, UserRole.analyst)),
    db: Session = Depends(get_db),
) -> DiscoveryRun:
    """Enqueues execution -- never runs the provider inside this
    request. The DiscoveryRun is created synchronously (status=queued)
    so the caller gets back a concrete id to poll via the existing
    GET /discovery/runs/{id}, exactly like the fully-synchronous
    POST /discovery/runs already lets a caller track a run by id, just
    without waiting for it to finish here.
    """
    schedule = _get_org_schedule_or_404(db, schedule_id, current_user.organization_id)
    if not schedule.enabled:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Schedule is disabled")

    run = discovery_scheduler_executor.claim_schedule_now(db, schedule)
    if run is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="A run is already in progress for this schedule"
        )

    from app.tasks.discovery_schedule_tasks import execute_scheduled_discovery_task

    execute_scheduled_discovery_task.delay(str(run.id), str(schedule.id))
    db.refresh(run)
    return run
