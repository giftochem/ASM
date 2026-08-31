"""Assembles the one shared, format-agnostic ReportData structure that
json_report/csv_report/pdf_report each render differently. Keeps
reporting logic out of the API layer entirely — routes only ever call
app.services.report_service, which calls this.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.core.enums import FindingSeverity
from app.models.asset import Asset
from app.models.finding import Finding
from app.models.organization import Organization
from app.models.scan import Scan
from app.services.risk_engine import compute_finding_risk_score


@dataclass
class ReportData:
    generated_at: datetime
    organization_name: str
    asset: dict
    scan: dict
    executive_summary: str
    findings_summary: dict
    risk_summary: dict
    findings: list[dict] = field(default_factory=list)


def _findings_summary(findings: list[Finding]) -> dict:
    counts = {s.value: 0 for s in FindingSeverity}
    for f in findings:
        counts[f.severity.value] += 1
    counts["total"] = len(findings)
    return counts


def _executive_summary(asset: Asset, scan: Scan, findings: list[Finding], summary: dict) -> str:
    if scan.status.value != "completed":
        return (
            f"Scan of {asset.value} did not complete successfully "
            f"(status: {scan.status.value}). {scan.error_message or ''}".strip()
        )
    if not findings:
        return f"Scan of {asset.value} completed with no findings."

    band = scan.risk_severity_band.value if scan.risk_severity_band else "minimal"
    notable = [f for f in findings if f.severity != FindingSeverity.info]
    return (
        f"Scan of {asset.value} completed with {summary['total']} finding(s) "
        f"({summary['critical']} critical, {summary['high']} high, {summary['medium']} medium, "
        f"{summary['low']} low, {summary['info']} informational). "
        f"Overall risk is assessed as '{band}'"
        f"{f' based on {len(notable)} actionable finding(s).' if notable else '.'}"
    )


def build_report_data(db: Session, scan: Scan) -> ReportData:
    asset = db.get(Asset, scan.asset_id)
    organization = db.get(Organization, asset.organization_id)
    findings = (
        db.query(Finding)
        .filter(Finding.scan_id == scan.id)
        .order_by(Finding.severity.desc(), Finding.created_at.asc())
        .all()
    )

    summary = _findings_summary(findings)
    scored = sorted(
        (
            {
                "id": str(f.id),
                "module": f.module,
                "title": f.title,
                "severity": f.severity.value,
                "risk_score": compute_finding_risk_score(f),
            }
            for f in findings
            if f.severity != FindingSeverity.info
        ),
        key=lambda x: x["risk_score"],
        reverse=True,
    )

    risk_summary = {
        "risk_score": scan.risk_score,
        "risk_severity_band": scan.risk_severity_band.value if scan.risk_severity_band else None,
        "top_findings": scored[:5],
    }

    findings_appendix = [
        {
            "id": str(f.id),
            "module": f.module,
            "title": f.title,
            "description": f.description,
            "severity": f.severity.value,
            "confidence": f.confidence,
            "exposure": f.exposure,
            "exploitability": f.exploitability,
            "risk_score": compute_finding_risk_score(f),
            "evidence": f.evidence,
            "created_at": f.created_at.isoformat(),
        }
        for f in findings
    ]

    return ReportData(
        generated_at=datetime.now(timezone.utc),
        organization_name=organization.name if organization else "Unknown",
        asset={
            "id": str(asset.id),
            "asset_type": asset.asset_type.value,
            "value": asset.value,
            "authorization_confirmed": asset.authorization_confirmed,
        },
        scan={
            "id": str(scan.id),
            "status": scan.status.value,
            "modules_requested": scan.modules_requested,
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            "error_message": scan.error_message,
        },
        executive_summary=_executive_summary(asset, scan, findings, summary),
        findings_summary=summary,
        risk_summary=risk_summary,
        findings=findings_appendix,
    )
