import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session, joinedload

from app.config import settings
from app.core.enums import UserRole
from app.core.exceptions import AuthorizationNotConfirmedError
from app.database import get_db
from app.dependencies import get_current_user, require_role
from app.models.asset import Asset
from app.models.scan import Scan
from app.models.user import User
from app.schemas.scan import ScanCreate, ScanRead, ScanResult
from app.services import scan_service
from app.services.rate_limit import limiter

router = APIRouter(prefix="/scans", tags=["scans"])


def _get_org_scan_or_404(db: Session, scan_id: uuid.UUID, organization_id: uuid.UUID) -> Scan:
    scan = (
        db.query(Scan)
        .join(Asset, Scan.asset_id == Asset.id)
        .options(joinedload(Scan.findings))
        .filter(Scan.id == scan_id, Asset.organization_id == organization_id)
        .first()
    )
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return scan


@router.get("", response_model=list[ScanRead])
def list_scans(
    asset_id: uuid.UUID | None = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[Scan]:
    query = (
        db.query(Scan)
        .join(Asset, Scan.asset_id == Asset.id)
        .filter(Asset.organization_id == current_user.organization_id)
    )
    if asset_id is not None:
        query = query.filter(Scan.asset_id == asset_id)
    return query.order_by(Scan.created_at.desc()).all()


@router.get("/{scan_id}", response_model=ScanResult)
def get_scan(
    scan_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Scan:
    return _get_org_scan_or_404(db, scan_id, current_user.organization_id)


@router.post("", response_model=ScanResult, status_code=status.HTTP_201_CREATED)
@limiter.limit(settings.rate_limit_scan_create)
def create_scan(
    payload: ScanCreate,
    request: Request,
    current_user: User = Depends(require_role(UserRole.admin, UserRole.analyst)),
    db: Session = Depends(get_db),
) -> Scan:
    """Validates synchronously (same 403/400 contract as Phase 1 — neither
    of those errors ever touches the network, so there's no reason to
    make the caller wait on a queue for them), then hands execution to a
    Celery worker. The response always reflects the scan's *current*
    state at the moment this returns: still `queued` under a real broker/
    worker, or already `completed` if executed inline (e.g. under the
    `eager_celery` test fixture) — the status code is always 201 either
    way, since a Scan resource genuinely was created in both cases.
    """
    asset = db.get(Asset, payload.asset_id)
    if asset is None or asset.organization_id != current_user.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")

    try:
        modules = scan_service.validate_scan_request(asset, payload.modules)
    except AuthorizationNotConfirmedError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    scan = scan_service.create_scan(db, asset, modules, current_user)
    scan_service.queue_scan(scan)

    # queue_scan may have already run execution to completion on a
    # *different* session (e.g. eager-mode Celery, or a real worker that
    # was fast enough) that committed further changes to this same scan
    # row. This session's identity map still holds the pre-execution
    # `scan` object from create_scan()'s db.refresh() above, and a plain
    # re-query does not overwrite an already-loaded, unexpired object's
    # attributes — so without expiring it first, this could return a
    # stale `status` even though the DB itself is current.
    db.expire(scan)

    return _get_org_scan_or_404(db, scan.id, current_user.organization_id)


@router.post("/{scan_id}/cancel", response_model=ScanRead)
def cancel_scan(
    scan_id: uuid.UUID,
    current_user: User = Depends(require_role(UserRole.admin, UserRole.analyst)),
    db: Session = Depends(get_db),
) -> Scan:
    """Only succeeds while the scan is still `queued` — once a worker has
    started it, cancellation here can't stop it (it can still be denied
    via revoking the asset's authorization, which scan_executor re-checks
    immediately before running any module).
    """
    scan = _get_org_scan_or_404(db, scan_id, current_user.organization_id)
    try:
        return scan_service.cancel_scan(db, scan)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
