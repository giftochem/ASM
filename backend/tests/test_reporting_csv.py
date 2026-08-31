import csv
import io
from datetime import datetime, timezone

from app.reporting.builder import ReportData
from app.reporting.csv_report import render


def _sample_data() -> ReportData:
    return ReportData(
        generated_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        organization_name="Acme Corp",
        asset={"id": "a1", "asset_type": "domain", "value": "example.com", "authorization_confirmed": True},
        scan={"id": "s1", "status": "completed"},
        executive_summary="Scan completed with 1 actionable finding.",
        findings_summary={"info": 1, "low": 0, "medium": 1, "high": 0, "critical": 0, "total": 2},
        risk_summary={"risk_score": 48.6, "risk_severity_band": "medium"},
        findings=[
            {
                "id": "f1",
                "module": "security_headers",
                "title": "Missing HSTS",
                "description": "No HSTS header present",
                "severity": "medium",
                "confidence": 0.9,
                "exposure": 1.0,
                "exploitability": 0.3,
                "risk_score": 48.6,
            }
        ],
    )


def test_csv_report_parses_and_contains_all_sections():
    content = render(_sample_data())
    text = content.decode("utf-8")
    rows = list(csv.reader(io.StringIO(text)))
    section_headers = [r[0] for r in rows if r and r[0].startswith("#")]

    assert "# Executive Summary" in section_headers
    assert "# Target / Asset Information" in section_headers
    assert "# Scan Metadata" in section_headers
    assert "# Findings Summary" in section_headers
    assert "# Risk Summary" in section_headers
    assert "# Technical Appendix: Findings" in section_headers


def test_csv_findings_table_has_expected_row():
    content = render(_sample_data())
    rows = list(csv.reader(io.StringIO(content.decode("utf-8"))))
    findings_header_idx = next(i for i, r in enumerate(rows) if r == ["# Technical Appendix: Findings"])
    column_header = rows[findings_header_idx + 1]
    data_row = rows[findings_header_idx + 2]

    assert column_header[0] == "id"
    assert "Missing HSTS" in data_row
    assert "medium" in data_row
