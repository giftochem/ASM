from datetime import datetime, timezone

import whois as pywhois

from app.core.enums import AssetType, FindingSeverity
from app.scanners.base import ScanFinding, ScanModuleResult, ScannerModule

_EXPIRY_WARNING_DAYS = 30


def _first(value):
    """python-whois sometimes returns a single value, sometimes a list
    (e.g. multiple creation_date entries from different WHOIS fields)."""
    if isinstance(value, list):
        return value[0] if value else None
    return value


class WhoisModule(ScannerModule):
    name = "whois"
    applicable_asset_types = {AssetType.domain}

    def run(self, target: str) -> ScanModuleResult:
        try:
            record = pywhois.whois(target)
        except Exception as exc:  # pywhois raises varied/undocumented exceptions per TLD
            return ScanModuleResult(module=self.name, error=f"WHOIS lookup failed: {exc}")

        if not record or not record.get("domain_name"):
            return ScanModuleResult(
                module=self.name,
                findings=[
                    ScanFinding(
                        title="No WHOIS record found",
                        description=f"WHOIS lookup for '{target}' returned no usable record.",
                        severity=FindingSeverity.info,
                        confidence=0.6,
                    )
                ],
            )

        registrar = _first(record.get("registrar"))
        creation_date = _first(record.get("creation_date"))
        expiration_date = _first(record.get("expiration_date"))
        name_servers = record.get("name_servers") or []
        if isinstance(name_servers, str):
            name_servers = [name_servers]

        findings = [
            ScanFinding(
                title="WHOIS record retrieved",
                description=f"Registrar: {registrar or 'unknown'}",
                severity=FindingSeverity.info,
                confidence=1.0,
                evidence={
                    "registrar": registrar,
                    "creation_date": str(creation_date) if creation_date else None,
                    "expiration_date": str(expiration_date) if expiration_date else None,
                    "name_servers": name_servers,
                },
            )
        ]

        if isinstance(expiration_date, datetime):
            expires_at = expiration_date
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
            days_left = (expires_at - datetime.now(timezone.utc)).days
            if days_left < 0:
                findings.append(
                    ScanFinding(
                        title="Domain registration has expired",
                        description=f"'{target}' expired {abs(days_left)} day(s) ago.",
                        severity=FindingSeverity.critical,
                        confidence=1.0,
                        evidence={"expiration_date": str(expiration_date)},
                    )
                )
            elif days_left <= _EXPIRY_WARNING_DAYS:
                findings.append(
                    ScanFinding(
                        title="Domain registration expiring soon",
                        description=f"'{target}' expires in {days_left} day(s). An expired "
                        "domain can be re-registered by a third party, enabling domain "
                        "hijacking of any services still pointing at it.",
                        severity=FindingSeverity.medium,
                        confidence=1.0,
                        evidence={"expiration_date": str(expiration_date)},
                    )
                )

        return ScanModuleResult(
            module=self.name,
            findings=findings,
            raw_data={
                "registrar": registrar,
                "creation_date": str(creation_date) if creation_date else None,
                "expiration_date": str(expiration_date) if expiration_date else None,
                "name_servers": name_servers,
                "status": record.get("status"),
                "emails": record.get("emails"),
            },
        )
