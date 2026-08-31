import uuid

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.core.enums import FindingSeverity
from app.database import get_db
from app.dependencies import get_current_user
from app.models.asset import Asset
from app.models.finding import Finding
from app.models.user import User
from app.schemas.finding import FindingRead

router = APIRouter(prefix="/findings", tags=["findings"])


@router.get("", response_model=list[FindingRead])
def list_findings(
    severity: FindingSeverity | None = None,
    module: str | None = None,
    asset_id: uuid.UUID | None = None,
    scan_id: uuid.UUID | None = None,
    limit: int = Query(default=100, le=500, ge=1),
    offset: int = Query(default=0, ge=0),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[Finding]:
    """Cross-scan findings view — read-only, available to every
    authenticated role (viewer included), same as GET /assets. Org-scoped
    via Finding.asset_id -> Asset.organization_id, same ownership-boundary
    pattern as every other resource in this API.
    """
    query = (
        db.query(Finding)
        .join(Asset, Finding.asset_id == Asset.id)
        .filter(Asset.organization_id == current_user.organization_id)
    )

    if severity is not None:
        query = query.filter(Finding.severity == severity)
    if module is not None:
        query = query.filter(Finding.module == module)
    if asset_id is not None:
        query = query.filter(Finding.asset_id == asset_id)
    if scan_id is not None:
        query = query.filter(Finding.scan_id == scan_id)

    return query.order_by(Finding.created_at.desc()).offset(offset).limit(limit).all()
