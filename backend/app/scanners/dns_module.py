import dns.exception
import dns.resolver

from app.core.enums import AssetType, FindingSeverity
from app.scanners.base import ScanFinding, ScanModuleResult, ScannerModule

_RECORD_TYPES = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA"]
_LOOKUP_TIMEOUT_SECONDS = 5.0


class DNSModule(ScannerModule):
    name = "dns"
    applicable_asset_types = {AssetType.domain, AssetType.subdomain}

    def run(self, target: str) -> ScanModuleResult:
        resolver = dns.resolver.Resolver()
        resolver.timeout = _LOOKUP_TIMEOUT_SECONDS
        resolver.lifetime = _LOOKUP_TIMEOUT_SECONDS

        records: list[dict] = []
        for record_type in _RECORD_TYPES:
            try:
                answer = resolver.resolve(target, record_type)
            except (
                dns.resolver.NXDOMAIN,
                dns.resolver.NoAnswer,
                dns.resolver.NoNameservers,
                dns.exception.Timeout,
            ):
                continue
            for rdata in answer:
                records.append(
                    {
                        "type": record_type,
                        "name": target,
                        "value": rdata.to_text(),
                        "ttl": answer.rrset.ttl if answer.rrset else None,
                    }
                )

        if not records:
            return ScanModuleResult(
                module=self.name,
                findings=[
                    ScanFinding(
                        title="No DNS records resolved",
                        description=f"None of {', '.join(_RECORD_TYPES)} resolved for '{target}'.",
                        severity=FindingSeverity.info,
                        confidence=0.7,
                    )
                ],
            )

        findings = [
            ScanFinding(
                title="DNS records enumerated",
                description=f"Resolved {len(records)} record(s) across "
                f"{len({r['type'] for r in records})} type(s) for '{target}'.",
                severity=FindingSeverity.info,
                confidence=1.0,
                evidence={"record_count": len(records)},
            )
        ]

        txt_values = [r["value"] for r in records if r["type"] == "TXT"]
        if not any("v=spf1" in v for v in txt_values):
            findings.append(
                ScanFinding(
                    title="No SPF record found",
                    description=f"'{target}' has no TXT record starting with 'v=spf1'. "
                    "Without SPF, mail claiming to be from this domain is easier to spoof.",
                    severity=FindingSeverity.medium,
                    confidence=0.8,
                )
            )

        if any(r["type"] == "MX" for r in records) and not any(
            "v=dmarc1" in v.lower() for v in txt_values
        ):
            # DMARC lives at _dmarc.<domain>, not the apex TXT set — this is a
            # coarse heuristic flag, not a definitive DMARC absence check.
            findings.append(
                ScanFinding(
                    title="Possible missing DMARC record",
                    description=f"'{target}' has mail (MX) records but no DMARC policy was "
                    "found in its apex TXT records. Verify _dmarc.{target} separately.",
                    severity=FindingSeverity.low,
                    confidence=0.4,
                )
            )

        return ScanModuleResult(module=self.name, findings=findings, raw_data={"records": records})
