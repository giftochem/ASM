"""Orchestrates report generation. Kept entirely separate from the API
layer — routes only call generate_report()/get_report_file(); all format
logic lives in app.reporting.
"""

import os
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.config import settings
from app.core.enums import ReportFormat, ReportStatus
from app.models.asset import Asset
from app.models.report import Report
from app.models.scan import Scan
from app.models.user import User
from app.reporting import csv_report, json_report, pdf_report
from app.reporting.builder import build_report_data
from app.services import audit_service

_RENDERERS = {
    ReportFormat.json: (json_report.render, "json"),
    ReportFormat.csv: (csv_report.render, "csv"),
    ReportFormat.pdf: (pdf_report.render, "pdf"),
}


def generate_report(db: Session, scan: Scan, format: ReportFormat, user: User) -> Report:
    report = Report(
        scan_id=scan.id,
        generated_by=user.id,
        format=format,
        status=ReportStatus.pending,
    )
    db.add(report)
    db.commit()
    db.refresh(report)

    report.status = ReportStatus.generating
    db.commit()

    try:
        data = build_report_data(db, scan)
        renderer, extension = _RENDERERS[format]
        content = renderer(data)

        os.makedirs(settings.reports_dir, exist_ok=True)
        file_path = os.path.join(settings.reports_dir, f"{report.id}.{extension}")
        with open(file_path, "wb") as f:
            f.write(content)

        report.storage_path = file_path
        report.status = ReportStatus.completed
        report.generated_at = datetime.now(timezone.utc)
        report.error_message = None
    except Exception as exc:  # a bad render must never look like a 500 to the caller
        report.status = ReportStatus.failed
        report.error_message = str(exc)

    asset = db.get(Asset, scan.asset_id)
    audit_service.log_action(
        db,
        user_id=user.id,
        organization_id=asset.organization_id if asset else None,
        action="report.generate",
        resource_type="report",
        resource_id=report.id,
        details={"scan_id": str(scan.id), "format": format.value, "status": report.status.value},
    )
    db.commit()
    db.refresh(report)
    return report
