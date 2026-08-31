"""Authorization-gated TCP connect-scan. The one active scanning module in
this codebase — everything else here is passive.

Scope deliberately narrow for this first pass:
- ip_address assets only, not ip_range. Scanning a whole range multiplies
  network impact and runtime by the number of hosts in it (up to 4096 at
  the default /20 cap) — real DoS-shaped risk against the target and a
  much bigger safety surface than a single host. Left out rather than
  shipped half-safe; would need its own per-scan host cap and stronger
  rate limiting to add responsibly.
- Only the ports in settings.allowed_scan_ports (never a free port range
  scan) — the same allowlist app.scanners.http_client already uses for
  its own outbound fetches.
- TCP connect scan only (plain socket.create_connection) — no raw
  sockets, no SYN scanning, no privilege escalation.

Every port probe re-validates the target through
app.scanners.net_safety.resolve_and_validate immediately before
connecting — the same primitive http_client uses — so this can never be
pointed at a loopback/private/link-local/reserved address even if
something upstream (asset creation validation) failed to catch it.
authorization_confirmed itself is enforced centrally by
app.services.scan_service (at request time) and re-checked, fail-closed,
by app.services.scan_executor immediately before this module — or any
module — runs; this file does not and should not re-implement that.
"""

import socket

from app.config import settings
from app.core.enums import AssetType, FindingSeverity
from app.scanners.base import ScanFinding, ScanModuleResult, ScannerModule
from app.scanners.net_safety import UnsafeTarget, resolve_and_validate

_CONNECT_TIMEOUT_SECONDS = 2.0


def _probe(ip: str, port: int) -> str:
    """Returns "open", "closed", or "filtered". A connect scan can tell
    a fast refusal (closed) apart from a timeout (filtered/firewalled),
    which is worth keeping even without a raw SYN scan.
    """
    try:
        with socket.create_connection((ip, port), timeout=_CONNECT_TIMEOUT_SECONDS):
            return "open"
    except ConnectionRefusedError:
        return "closed"
    except (OSError, socket.timeout):
        return "filtered"


class PortScannerModule(ScannerModule):
    name = "port_scanner"
    applicable_asset_types = {AssetType.ip_address}
    requires_explicit_opt_in = True

    def run(self, target: str) -> ScanModuleResult:
        ports_to_scan = sorted(settings.allowed_scan_ports)
        port_states: dict[int, str] = {}

        for port in ports_to_scan:
            validation = resolve_and_validate(target, port)
            if isinstance(validation, UnsafeTarget):
                return ScanModuleResult(
                    module=self.name, error=f"blocked target '{target}:{port}': {validation.reason}"
                )
            port_states[port] = _probe(validation.resolved_ips[0], port)

        open_ports = sorted(p for p, state in port_states.items() if state == "open")

        findings = [
            ScanFinding(
                title="Port scan completed",
                description=f"Scanned {len(port_states)} port(s) on {target}: "
                f"{len(open_ports)} open.",
                severity=FindingSeverity.info,
                confidence=1.0,
                exposure=1.0,
                exploitability=0.0,
                evidence={"ports_scanned": ports_to_scan, "open_ports": open_ports},
            )
        ]
        for port in open_ports:
            findings.append(
                ScanFinding(
                    title=f"Open port: {port}/tcp",
                    description=f"{target}:{port} accepted a TCP connection.",
                    severity=FindingSeverity.low,
                    confidence=1.0,
                    exposure=1.0,
                    exploitability=0.2,
                    evidence={"port": port, "protocol": "tcp"},
                )
            )

        return ScanModuleResult(
            module=self.name,
            findings=findings,
            raw_data={
                "ports": [
                    {"port": port, "protocol": "tcp", "state": state}
                    for port, state in port_states.items()
                ]
            },
        )
