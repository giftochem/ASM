"""Passive technology fingerprinting: HTTP response headers + response body
signature matching only. Never executes fetched content — every check
below is a plain string/substring/regex match against text already
fetched (and size-capped) by http_client. No JS execution, no rendering.
"""

import re
from dataclasses import dataclass

from app.core.enums import AssetType, FindingSeverity
from app.scanners.base import ScanFinding, ScanModuleResult, ScannerModule
from app.scanners.http_client import FetchError, RequestScope, ScopeRejection, fetch


@dataclass
class _HeaderSignature:
    header: str
    pattern: re.Pattern
    name: str
    category: str


@dataclass
class _BodySignature:
    pattern: re.Pattern
    name: str
    category: str


_HEADER_SIGNATURES = [
    _HeaderSignature("server", re.compile(r"nginx", re.I), "nginx", "web-server"),
    _HeaderSignature("server", re.compile(r"apache", re.I), "Apache HTTP Server", "web-server"),
    _HeaderSignature("server", re.compile(r"microsoft-iis", re.I), "Microsoft IIS", "web-server"),
    _HeaderSignature("server", re.compile(r"cloudflare", re.I), "Cloudflare", "cdn"),
    _HeaderSignature("x-powered-by", re.compile(r"php", re.I), "PHP", "language"),
    _HeaderSignature("x-powered-by", re.compile(r"express", re.I), "Express", "framework"),
    _HeaderSignature("x-powered-by", re.compile(r"asp\.net", re.I), "ASP.NET", "framework"),
    _HeaderSignature("x-aspnet-version", re.compile(r".+"), "ASP.NET", "framework"),
    _HeaderSignature("x-aspnetmvc-version", re.compile(r".+"), "ASP.NET MVC", "framework"),
    _HeaderSignature("x-generator", re.compile(r".+"), "Generator (via X-Generator)", "cms"),
    _HeaderSignature("set-cookie", re.compile(r"PHPSESSID", re.I), "PHP", "language"),
    _HeaderSignature("set-cookie", re.compile(r"JSESSIONID", re.I), "Java (Servlet container)", "language"),
    _HeaderSignature("set-cookie", re.compile(r"laravel_session", re.I), "Laravel", "framework"),
    _HeaderSignature("set-cookie", re.compile(r"wordpress_logged_in"), "WordPress", "cms"),
    _HeaderSignature("set-cookie", re.compile(r"csrftoken"), "Django", "framework"),
]

_BODY_SIGNATURES = [
    _BodySignature(re.compile(r'name=["\']generator["\'] content=["\']WordPress', re.I), "WordPress", "cms"),
    _BodySignature(re.compile(r"wp-content/|wp-includes/", re.I), "WordPress", "cms"),
    _BodySignature(re.compile(r'name=["\']generator["\'] content=["\']Drupal', re.I), "Drupal", "cms"),
    _BodySignature(re.compile(r"/sites/default/files", re.I), "Drupal", "cms"),
    _BodySignature(re.compile(r'name=["\']generator["\'] content=["\']Joomla', re.I), "Joomla", "cms"),
    _BodySignature(re.compile(r"cdn\.shopify\.com|Shopify\.theme"), "Shopify", "ecommerce"),
    _BodySignature(re.compile(r"__NEXT_DATA__"), "Next.js", "javascript-framework"),
    _BodySignature(re.compile(r"data-reactroot|react-dom"), "React", "javascript-library"),
    _BodySignature(re.compile(r"ng-version="), "Angular", "javascript-framework"),
    _BodySignature(re.compile(r"id=[\"']__nuxt[\"']"), "Nuxt.js", "javascript-framework"),
]


class TechnologyModule(ScannerModule):
    name = "technology"
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

        detected: dict[str, dict] = {}

        for sig in _HEADER_SIGNATURES:
            value = result.headers.get(sig.header)
            if value and sig.pattern.search(value):
                detected.setdefault(
                    sig.name,
                    {
                        "name": sig.name,
                        "category": sig.category,
                        "detection_method": f"header:{sig.header}",
                        "confidence": 0.8,
                    },
                )

        for sig in _BODY_SIGNATURES:
            if sig.pattern.search(result.text):
                detected.setdefault(
                    sig.name,
                    {
                        "name": sig.name,
                        "category": sig.category,
                        "detection_method": "body-signature",
                        "confidence": 0.7,
                    },
                )

        technologies = list(detected.values())

        findings = [
            ScanFinding(
                title="Technology fingerprint completed"
                if technologies
                else "No known technology signatures detected",
                description=f"Detected {len(technologies)} technology signature(s) at {result.final_url}."
                if technologies
                else f"No recognized technology signatures found at {result.final_url}.",
                severity=FindingSeverity.info,
                confidence=1.0,
                exposure=1.0,
                exploitability=0.0,
                evidence={"technologies": [t["name"] for t in technologies], "url": result.final_url},
            )
        ]

        return ScanModuleResult(
            module=self.name,
            findings=findings,
            raw_data={"technologies": technologies, "final_url": result.final_url},
        )
