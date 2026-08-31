"""Common interface every scanner module implements.

Modules never decide for themselves whether they're allowed to run — that
gate (authorization_confirmed on the target Asset) is enforced by
app.services.scan_service (at scan-creation time) and re-enforced by
app.services.scan_executor (immediately before module execution, fail
closed) — never by the modules themselves. A module's job is just: given
an already-validated target string, return findings plus any
module-specific structured data.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import ClassVar

from app.core.enums import AssetType, FindingSeverity


@dataclass
class ScanFinding:
    title: str
    description: str
    severity: FindingSeverity = FindingSeverity.info
    confidence: float = 1.0
    # See app/models/finding.py for what these represent; risk_engine
    # combines both with severity + confidence into a bounded score.
    exposure: float = 1.0
    exploitability: float = 0.5
    evidence: dict = field(default_factory=dict)


@dataclass
class ScanModuleResult:
    module: str
    findings: list[ScanFinding] = field(default_factory=list)
    # Module-specific structured data the scan pipeline knows how to persist
    # into specialized tables (e.g. dns -> DNSRecord rows, ssl -> SSLInfo row).
    raw_data: dict = field(default_factory=dict)
    error: str | None = None


class ScannerModule(ABC):
    name: ClassVar[str]
    applicable_asset_types: ClassVar[set[AssetType]]
    # True for active-scanning modules (currently just port_scanner) that
    # must never run just because a caller omitted `modules` from a scan
    # request. scan_service.validate_scan_request excludes any module
    # with this set from the "run everything applicable" default — such
    # a module only ever runs if named explicitly in the request.
    requires_explicit_opt_in: ClassVar[bool] = False

    def supports(self, asset_type: AssetType) -> bool:
        return asset_type in self.applicable_asset_types

    @abstractmethod
    def run(self, target: str) -> ScanModuleResult:
        """Execute the module against an already-validated target string.

        Must not raise for expected failure modes (target unreachable, no
        records found, etc.) — return a ScanModuleResult with `error` set
        instead, so one failing module doesn't abort the whole scan.
        """
        raise NotImplementedError
