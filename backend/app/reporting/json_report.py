import json

from app.reporting.builder import ReportData


def render(data: ReportData) -> bytes:
    payload = {
        "generated_at": data.generated_at.isoformat(),
        "organization": data.organization_name,
        "asset": data.asset,
        "scan": data.scan,
        "executive_summary": data.executive_summary,
        "findings_summary": data.findings_summary,
        "risk_summary": data.risk_summary,
        "technical_appendix": {"findings": data.findings},
    }
    return json.dumps(payload, indent=2, default=str).encode("utf-8")
