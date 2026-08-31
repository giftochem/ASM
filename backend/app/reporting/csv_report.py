import csv
import io

from app.reporting.builder import ReportData


def render(data: ReportData) -> bytes:
    buf = io.StringIO()
    writer = csv.writer(buf)

    writer.writerow(["# Executive Summary"])
    writer.writerow([data.executive_summary])
    writer.writerow([])

    writer.writerow(["# Target / Asset Information"])
    for key, value in data.asset.items():
        writer.writerow([key, value])
    writer.writerow([])

    writer.writerow(["# Scan Metadata"])
    for key, value in data.scan.items():
        writer.writerow([key, value])
    writer.writerow([])

    writer.writerow(["# Findings Summary"])
    for key, value in data.findings_summary.items():
        writer.writerow([key, value])
    writer.writerow([])

    writer.writerow(["# Risk Summary"])
    writer.writerow(["risk_score", data.risk_summary["risk_score"]])
    writer.writerow(["risk_severity_band", data.risk_summary["risk_severity_band"]])
    writer.writerow([])

    writer.writerow(["# Technical Appendix: Findings"])
    writer.writerow(
        ["id", "module", "title", "severity", "confidence", "exposure", "exploitability", "risk_score", "description"]
    )
    for f in data.findings:
        writer.writerow(
            [
                f["id"],
                f["module"],
                f["title"],
                f["severity"],
                f["confidence"],
                f["exposure"],
                f["exploitability"],
                f["risk_score"],
                f["description"] or "",
            ]
        )

    return buf.getvalue().encode("utf-8")
