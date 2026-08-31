import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.enums import AlertPriority, AlertStatus, AlertType, UserRole
from app.database import get_db
from app.dependencies import get_current_user, require_role
from app.models.alert import Alert
from app.models.user import User
from app.schemas.alert import AlertRead
from app.services import alert_service

router = APIRouter(prefix="/alerts", tags=["alerts"])


def _get_org_alert_or_404(db: Session, alert_id: uuid.UUID, organization_id: uuid.UUID) -> Alert:
    alert = db.get(Alert, alert_id)
    if alert is None or alert.organization_id != organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
    return alert


@router.get("", response_model=list[AlertRead])
def list_alerts(
    status_filter: list[AlertStatus] | None = Query(default=None, alias="status"),
    priority: list[AlertPriority] | None = Query(default=None),
    alert_type: list[AlertType] | None = Query(default=None),
    asset_id: uuid.UUID | None = Query(default=None),
    before_last_seen_at: datetime | None = Query(default=None),
    before_id: uuid.UUID | None = Query(default=None),
    limit: int = Query(default=alert_service.DEFAULT_ALERT_LIST_LIMIT, ge=1, le=alert_service.MAX_ALERT_LIST_LIMIT),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[Alert]:
    return alert_service.list_alerts(
        db,
        current_user.organization_id,
        statuses=status_filter,
        priorities=priority,
        alert_types=alert_type,
        asset_id=asset_id,
        before_last_seen_at=before_last_seen_at,
        before_id=before_id,
        limit=limit,
    )


@router.get("/{alert_id}", response_model=AlertRead)
def get_alert(
    alert_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Alert:
    return _get_org_alert_or_404(db, alert_id, current_user.organization_id)


@router.post("/{alert_id}/acknowledge", response_model=AlertRead)
def acknowledge_alert(
    alert_id: uuid.UUID,
    current_user: User = Depends(require_role(UserRole.admin, UserRole.analyst)),
    db: Session = Depends(get_db),
) -> Alert:
    alert = _get_org_alert_or_404(db, alert_id, current_user.organization_id)
    try:
        return alert_service.acknowledge_alert(db, alert, current_user.id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.post("/{alert_id}/resolve", response_model=AlertRead)
def resolve_alert(
    alert_id: uuid.UUID,
    current_user: User = Depends(require_role(UserRole.admin, UserRole.analyst)),
    db: Session = Depends(get_db),
) -> Alert:
    alert = _get_org_alert_or_404(db, alert_id, current_user.organization_id)
    try:
        return alert_service.resolve_alert(db, alert, current_user.id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
