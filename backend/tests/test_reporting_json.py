import json
from datetime import datetime, timezone

from app.reporting.builder import ReportData
from app.reporting.json_report import render


def _sample_data() -> ReportData:
    return ReportData(
        generated_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        organization_name="Acme Corp",
        asset={"id": "a1", "asset_type": "domain", "value": "example.com", "authorization_confirmed": True},
        scan={"id": "s1", "status": "completed", "modules_requested": ["dns", "ssl"]},
        executive_summary="Scan completed with 1 finding (0 critical, ...).",
        findings_summary={"info": 1, "low": 0, "medium": 1, "high": 0, "critical": 0, "total": 2},
        risk_summary={"risk_score": 48.6, "risk_severity_band": "medium", "top_findings": []},
        findings=[
            {
                "id": "f1",
                "module": "security_headers",
                "title": "Missing HSTS",
                "description": "desc",
                "severity": "medium",
                "confidence": 0.9,
                "exposure": 1.0,
                "exploitability": 0.3,
                "risk_score": 48.6,
                "evidence": {"a": 1},
                "created_at": "2026-01-01T00:00:00+00:00",
            }
        ],
    )


def test_json_report_contains_all_required_sections():
    payload = json.loads(render(_sample_data()))
    for key in (
        "generated_at",
        "organization",
        "asset",
        "scan",
        "executive_summary",
        "findings_summary",
        "risk_summary",
        "technical_appendix",
    ):
        assert key in payload

    assert payload["asset"]["value"] == "example.com"
    assert payload["risk_summary"]["risk_score"] == 48.6
    assert len(payload["technical_appendix"]["findings"]) == 1
    assert payload["technical_appendix"]["findings"][0]["title"] == "Missing HSTS"


def test_json_report_is_valid_utf8_bytes():
    content = render(_sample_data())
    assert isinstance(content, bytes)
    json.loads(content.decode("utf-8"))  # must not raise
