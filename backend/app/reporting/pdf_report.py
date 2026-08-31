"""PDF rendering via reportlab. Text derived from a scanned target (header
values, WHOIS fields, etc. embedded in finding descriptions) is untrusted
input by the time it reaches here, so everything passed to a reportlab
Paragraph — which interprets a small XML-like markup subset — is escaped
first. Table cells are passed as plain strings (not Paragraph objects),
which reportlab does not markup-parse, but they're escaped too for
defense in depth and consistency.
"""

from io import BytesIO
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from app.reporting.builder import ReportData

_TABLE_STYLE = TableStyle(
    [
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("BACKGROUND", (0, 0), (-1, 0), colors.whitesmoke),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]
)


def _kv_table(data: dict) -> Table:
    rows = [[escape(str(k)), escape(str(v))] for k, v in data.items()]
    table = Table(rows, colWidths=[150, 350])
    table.setStyle(_TABLE_STYLE)
    return table


def render(data: ReportData) -> bytes:
    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter, title="ASM Scan Report")
    styles = getSampleStyleSheet()
    story = []

    story.append(Paragraph("Attack Surface Mapper — Scan Report", styles["Title"]))
    story.append(
        Paragraph(
            f"Generated: {escape(data.generated_at.isoformat())} | "
            f"Organization: {escape(data.organization_name)}",
            styles["Normal"],
        )
    )
    story.append(Spacer(1, 16))

    story.append(Paragraph("Executive Summary", styles["Heading2"]))
    story.append(Paragraph(escape(data.executive_summary), styles["Normal"]))
    story.append(Spacer(1, 12))

    story.append(Paragraph("Target / Asset Information", styles["Heading2"]))
    story.append(_kv_table(data.asset))
    story.append(Spacer(1, 12))

    story.append(Paragraph("Scan Metadata", styles["Heading2"]))
    story.append(_kv_table(data.scan))
    story.append(Spacer(1, 12))

    story.append(Paragraph("Findings Summary", styles["Heading2"]))
    story.append(_kv_table(data.findings_summary))
    story.append(Spacer(1, 12))

    story.append(Paragraph("Risk Summary", styles["Heading2"]))
    story.append(_kv_table(data.risk_summary))
    story.append(Spacer(1, 16))

    story.append(Paragraph("Technical Appendix", styles["Heading2"]))
    if data.findings:
        header = ["Module", "Title", "Severity", "Confidence", "Risk Score"]
        rows = [header] + [
            [
                escape(f["module"]),
                escape(f["title"]),
                escape(f["severity"]),
                escape(str(f["confidence"])),
                escape(str(f["risk_score"])),
            ]
            for f in data.findings
        ]
        appendix_table = Table(rows, repeatRows=1, colWidths=[70, 200, 60, 65, 65])
        appendix_table.setStyle(_TABLE_STYLE)
        story.append(appendix_table)
    else:
        story.append(Paragraph("No findings.", styles["Normal"]))

    doc.build(story)
    return buf.getvalue()
