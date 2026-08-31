import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.core.enums import ReportStatus, UserRole
from app.database import get_db
from app.dependencies import get_current_user, require_role
from app.models.asset import Asset
from app.models.report import Report
from app.models.scan import Scan
from app.models.user import User
from app.schemas.report import ReportCreate, ReportRead
from app.services.report_service import generate_report

router = APIRouter(prefix="/reports", tags=["reports"])

_MEDIA_TYPES = {
    "json": "application/json",
    "csv": "text/csv",
    "pdf": "application/pdf",
}


def _get_org_report_or_404(db: Session, report_id: uuid.UUID, organization_id: uuid.UUID) -> Report:
    report = (
        db.query(Report)
        .join(Scan, Report.scan_id == Scan.id)
        .join(Asset, Scan.asset_id == Asset.id)
        .filter(Report.id == report_id, Asset.organization_id == organization_id)
        .first()
    )
    if report is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")
    return report


@router.get("", response_model=list[ReportRead])
def list_reports(
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> list[Report]:
    return (
        db.query(Report)
        .join(Scan, Report.scan_id == Scan.id)
        .join(Asset, Scan.asset_id == Asset.id)
        .filter(Asset.organization_id == current_user.organization_id)
        .order_by(Report.created_at.desc())
        .all()
    )


@router.get("/{report_id}", response_model=ReportRead)
def get_report(
    report_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Report:
    return _get_org_report_or_404(db, report_id, current_user.organization_id)


@router.get("/{report_id}/download")
def download_report(
    report_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> FileResponse:
    report = _get_org_report_or_404(db, report_id, current_user.organization_id)
    if report.status != ReportStatus.completed or not report.storage_path:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Report is not available for download (status: {report.status.value})",
        )
    media_type = _MEDIA_TYPES.get(report.format.value, "application/octet-stream")
    filename = f"asm-report-{report.id}.{report.format.value}"
    return FileResponse(report.storage_path, media_type=media_type, filename=filename)


@router.post("", response_model=ReportRead, status_code=status.HTTP_201_CREATED)
def create_report(
    payload: ReportCreate,
    current_user: User = Depends(require_role(UserRole.admin, UserRole.analyst)),
    db: Session = Depends(get_db),
) -> Report:
    scan = (
        db.query(Scan)
        .join(Asset, Scan.asset_id == Asset.id)
        .filter(Scan.id == payload.scan_id, Asset.organization_id == current_user.organization_id)
        .first()
    )
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    return generate_report(db, scan, payload.format, current_user)
