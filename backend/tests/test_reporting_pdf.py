from datetime import datetime, timezone

from app.reporting.builder import ReportData
from app.reporting.pdf_report import render


def _sample_data(title="Missing HSTS", description="No HSTS header present") -> ReportData:
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
                "title": title,
                "description": description,
                "severity": "medium",
                "confidence": 0.9,
                "exposure": 1.0,
                "exploitability": 0.3,
                "risk_score": 48.6,
            }
        ],
    )


def test_pdf_report_produces_valid_pdf_bytes():
    content = render(_sample_data())
    assert isinstance(content, bytes)
    assert content.startswith(b"%PDF-")
    assert content.rstrip().endswith(b"%%EOF")


def test_pdf_report_handles_no_findings():
    data = _sample_data()
    data.findings = []
    content = render(data)
    assert content.startswith(b"%PDF-")


def test_pdf_report_escapes_untrusted_header_derived_text():
    """A finding's title/description can embed raw text from the scanned
    target (e.g. an actual HTTP header value) — reportlab's Paragraph
    interprets a small XML-like markup subset, so unescaped '<'/'&' from
    that untrusted text must not reach it unescaped. This just needs to
    render without raising and produce a normal PDF, not any specific
    parsed structure.
    """
    malicious = "Unrecognized value: <b>&injected</b><script>x</script>"
    content = render(_sample_data(title=malicious, description=malicious))
    assert content.startswith(b"%PDF-")
