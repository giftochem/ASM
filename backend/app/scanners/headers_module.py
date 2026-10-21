"""Passive HTTP security-header analysis. Severity is deliberately capped
at `medium` for every check here — an absent optional header is a
defense-in-depth gap, not on its own proof of an exploitable issue, per
explicit product guidance. Nothing here is ever `critical`.
"""

import re

from app.core.enums import AssetType, FindingSeverity
from app.scanners.base import ScanFinding, ScanModuleResult, ScannerModule
from app.scanners.http_client import FetchError, RequestScope, ScopeRejection, fetch

_HSTS_MIN_MAX_AGE = 15768000  # ~6 months, a common minimum recommendation
_WEAK_CSP_TOKENS = ("unsafe-inline", "unsafe-eval", "*")
_VALID_X_FRAME_OPTIONS = {"deny", "sameorigin"}
_VALID_REFERRER_POLICIES = {
    "no-referrer",
    "no-referrer-when-downgrade",
    "origin",
    "origin-when-cross-origin",
    "same-origin",
    "strict-origin",
    "strict-origin-when-cross-origin",
    "unsafe-url",
}


class HeadersModule(ScannerModule):
    name = "security_headers"
    applicable_asset_types = {
        AssetType.domain,
        AssetType.subdomain,
        AssetType.ip_address,
        AssetType.url,
    }

    def run(self, target: str) -> ScanModuleResult:
        # Only the target's own scope is ever fetched: a redirect elsewhere
        # is not followed, and nothing from another site is attributed here.
        result = fetch(target, scope=RequestScope.for_target(target))
        if isinstance(result, (FetchError, ScopeRejection)):
            return ScanModuleResult(module=self.name, error=result.reason)

        headers = {k.lower(): v for k, v in result.headers.items()}
        findings: list[ScanFinding] = []

        findings.extend(self._check_hsts(headers, result.final_url))
        findings.extend(self._check_csp(headers))
        findings.extend(self._check_x_content_type_options(headers))
        findings.extend(self._check_x_frame_options(headers, headers.get("content-security-policy", "")))
        findings.extend(self._check_referrer_policy(headers))
        findings.extend(self._check_permissions_policy(headers))

        findings.append(
            ScanFinding(
                title="Security header analysis completed",
                description=f"Checked 6 security headers on {result.final_url} "
                f"(HTTP {result.status_code}).",
                severity=FindingSeverity.info,
                confidence=1.0,
                exposure=1.0,
                exploitability=0.0,
                evidence={"status_code": result.status_code, "url": result.final_url},
            )
        )

        return ScanModuleResult(
            module=self.name,
            findings=findings,
            raw_data={"headers_present": sorted(headers.keys()), "final_url": result.final_url},
        )

    @staticmethod
    def _check_hsts(headers: dict[str, str], url: str) -> list[ScanFinding]:
        value = headers.get("strict-transport-security")
        if not url.startswith("https://"):
            return []  # HSTS is meaningless to demand over plain HTTP
        if not value:
            return [
                ScanFinding(
                    title="Missing Strict-Transport-Security header",
                    description="HTTPS is served without HSTS, so browsers won't enforce HTTPS "
                    "on subsequent visits — a downgrade/stripping window, not an immediate compromise.",
                    severity=FindingSeverity.medium,
                    confidence=0.9,
                    exploitability=0.3,
                )
            ]
        match = re.search(r"max-age=(\d+)", value, re.I)
        max_age = int(match.group(1)) if match else 0
        if max_age == 0:
            return [
                ScanFinding(
                    title="HSTS explicitly disabled (max-age=0)",
                    description=f"Strict-Transport-Security is present but max-age=0: '{value}'.",
                    severity=FindingSeverity.medium,
                    confidence=0.95,
                    exploitability=0.3,
                    evidence={"value": value},
                )
            ]
        if max_age < _HSTS_MIN_MAX_AGE:
            return [
                ScanFinding(
                    title="HSTS max-age is shorter than recommended",
                    description=f"max-age={max_age}s is below the commonly recommended "
                    f"{_HSTS_MIN_MAX_AGE}s (~6 months): '{value}'.",
                    severity=FindingSeverity.low,
                    confidence=0.7,
                    exploitability=0.2,
                    evidence={"value": value},
                )
            ]
        return []

    @staticmethod
    def _check_csp(headers: dict[str, str]) -> list[ScanFinding]:
        value = headers.get("content-security-policy")
        if not value:
            return [
                ScanFinding(
                    title="Missing Content-Security-Policy header",
                    description="No CSP means the browser applies no restriction on script/resource "
                    "sources beyond same-origin defaults — a defense-in-depth gap against XSS, "
                    "not proof an XSS exists.",
                    severity=FindingSeverity.low,
                    confidence=0.8,
                    exploitability=0.2,
                )
            ]
        weak_tokens = [t for t in _WEAK_CSP_TOKENS if t in value]
        if weak_tokens:
            return [
                ScanFinding(
                    title="Content-Security-Policy contains weak directives",
                    description=f"CSP includes {', '.join(weak_tokens)}, which significantly "
                    "weakens its protection against script injection.",
                    severity=FindingSeverity.medium,
                    confidence=0.75,
                    exploitability=0.4,
                    evidence={"value": value},
                )
            ]
        return []

    @staticmethod
    def _check_x_content_type_options(headers: dict[str, str]) -> list[ScanFinding]:
        value = headers.get("x-content-type-options")
        if not value:
            return [
                ScanFinding(
                    title="Missing X-Content-Type-Options header",
                    description="Without 'nosniff', some browsers may MIME-sniff responses, "
                    "which can enable content-type confusion attacks in edge cases.",
                    severity=FindingSeverity.low,
                    confidence=0.8,
                    exploitability=0.15,
                )
            ]
        if value.strip().lower() != "nosniff":
            return [
                ScanFinding(
                    title="Unrecognized X-Content-Type-Options value",
                    description=f"Expected 'nosniff', got '{value}'.",
                    severity=FindingSeverity.low,
                    confidence=0.9,
                    exploitability=0.15,
                    evidence={"value": value},
                )
            ]
        return []

    @staticmethod
    def _check_x_frame_options(headers: dict[str, str], csp_value: str) -> list[ScanFinding]:
        value = headers.get("x-frame-options")
        has_frame_ancestors = "frame-ancestors" in csp_value.lower()
        if not value:
            if has_frame_ancestors:
                return []  # CSP frame-ancestors already covers this
            return [
                ScanFinding(
                    title="Missing X-Frame-Options header",
                    description="No clickjacking protection via X-Frame-Options and no CSP "
                    "frame-ancestors directive either.",
                    severity=FindingSeverity.low,
                    confidence=0.8,
                    exploitability=0.2,
                )
            ]
        if value.strip().lower() not in _VALID_X_FRAME_OPTIONS:
            return [
                ScanFinding(
                    title="Unrecognized X-Frame-Options value",
                    description=f"Expected DENY or SAMEORIGIN, got '{value}'.",
                    severity=FindingSeverity.low,
                    confidence=0.85,
                    exploitability=0.2,
                    evidence={"value": value},
                )
            ]
        return []

    @staticmethod
    def _check_referrer_policy(headers: dict[str, str]) -> list[ScanFinding]:
        value = headers.get("referrer-policy")
        if not value:
            return [
                ScanFinding(
                    title="Missing Referrer-Policy header",
                    description="No explicit referrer policy — browsers fall back to their own "
                    "default, which can leak full URLs (including query strings) to third parties "
                    "via the Referer header on outbound navigation/requests.",
                    severity=FindingSeverity.info,
                    confidence=0.7,
                    exploitability=0.1,
                )
            ]
        first_token = value.split(",")[0].strip().lower()
        if first_token not in _VALID_REFERRER_POLICIES:
            return [
                ScanFinding(
                    title="Unrecognized Referrer-Policy value",
                    description=f"'{value}' is not a recognized Referrer-Policy directive.",
                    severity=FindingSeverity.low,
                    confidence=0.6,
                    exploitability=0.1,
                    evidence={"value": value},
                )
            ]
        return []

    @staticmethod
    def _check_permissions_policy(headers: dict[str, str]) -> list[ScanFinding]:
        if not headers.get("permissions-policy"):
            return [
                ScanFinding(
                    title="Missing Permissions-Policy header",
                    description="No Permissions-Policy header — browser features (camera, "
                    "geolocation, etc.) aren't explicitly restricted. Minor hygiene gap.",
                    severity=FindingSeverity.info,
                    confidence=0.6,
                    exploitability=0.05,
                )
            ]
        return []
