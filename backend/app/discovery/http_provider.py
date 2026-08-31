"""Passive HTTP/HTTPS reachability and metadata intelligence for an
authorized domain/subdomain/url seed (Step 9.5). Bounded intelligence
collection, NOT a vulnerability scanner: no exploitation, no crawling,
no brute-force endpoint discovery, no credential attacks.

Reuses app.scanners.http_client.fetch_url (the same SSRF-hardened fetch
primitive headers_module/technology_module already use — resolves and
validates every hop through net_safety, pins the TCP connection to the
validated IP to close DNS rebinding, caps redirects/timeouts/response
size) rather than reimplementing any of that. `fetch_url` (unlike
`fetch()`) attempts exactly the one URL it's given, with no scheme
fallback — called independently once per scheme here, so "HTTPS
reachable" and "HTTP reachable" are reported as two separate signals
instead of "the first one that worked."

SAFETY: fetch_url's redirect handling is SSRF-safe (no private/loopback/
link-local destination) but has no concept of *authorization scope* —
that's correct for its existing active-scan callers (an authorized
target is expected to redirect wherever it wants), but wrong for
discovery, where a redirect can land on a genuinely different,
unauthorized entity. This module adds that scope check on top, against
the final response URL only: if the final destination has left the
seed's authorized scope (app.core.validation.is_hostname_in_scope), the
observation still records the fact of the redirect, but nothing about
that destination (headers/title/technology) is captured or attributed
to the org.
"""

import re
from urllib.parse import urlparse

from app.core.enums import AssetType
from app.core.validation import is_hostname_in_scope
from app.discovery.base import DiscoveryProvider, DiscoveryProviderResult, HttpObservation
from app.scanners import http_client
from app.scanners.http_client import FetchError, FetchResult

_SECURITY_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
)

# Deliberately narrow and provider-local -- NOT app.scanners.technology_module's
# fuller signature list, which feeds human-reviewed scan findings and is
# intentionally more speculative. Confidence values match the examples
# given in the Step 9.5 spec: header-derived signals are more reliable
# than a single HTML marker.
_HEADER_TECH_SIGNATURES = (
    ("server", re.compile(r"nginx", re.I), "nginx", 0.8, "Server header"),
    ("server", re.compile(r"apache", re.I), "Apache HTTP Server", 0.8, "Server header"),
    ("server", re.compile(r"microsoft-iis", re.I), "Microsoft IIS", 0.8, "Server header"),
    ("server", re.compile(r"cloudflare", re.I), "Cloudflare", 0.8, "Server header"),
    ("x-powered-by", re.compile(r"php", re.I), "PHP", 0.7, "X-Powered-By header"),
    ("x-powered-by", re.compile(r"express", re.I), "Express", 0.7, "X-Powered-By header"),
    ("x-powered-by", re.compile(r"asp\.net", re.I), "ASP.NET", 0.7, "X-Powered-By header"),
)
_GENERATOR_META_RE = re.compile(r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)["\']', re.I)
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_MAX_TITLE_LENGTH = 500


def _seed_hostname(seed_value: str) -> str:
    """is_hostname_in_scope expects a bare hostname. For a url-type seed
    (e.g. "https://api.example.com/path"), that's its host component; for
    a bare domain/subdomain seed it's the value itself.
    """
    if seed_value.startswith("http://") or seed_value.startswith("https://"):
        return urlparse(seed_value).hostname or seed_value
    return seed_value


def _extract_title(html_text: str) -> str | None:
    match = _TITLE_RE.search(html_text)
    if not match:
        return None
    title = re.sub(r"\s+", " ", match.group(1)).strip()
    return title[:_MAX_TITLE_LENGTH] if title else None


def _infer_technology(headers: dict[str, str], html_text: str) -> list[dict]:
    evidence = []
    for header_name, pattern, technology, confidence, evidence_label in _HEADER_TECH_SIGNATURES:
        value = headers.get(header_name)
        if value and pattern.search(value):
            evidence.append({"technology": technology, "confidence": confidence, "evidence": evidence_label})
    if html_text:
        match = _GENERATOR_META_RE.search(html_text)
        if match:
            generator = match.group(1).strip()[:100]
            if generator:
                evidence.append({"technology": generator, "confidence": 0.5, "evidence": "HTML generator meta tag"})
    return evidence


def _parse_cookie_flags(raw_cookie: str) -> dict:
    """Only ever looks at attributes after the first ';' -- the
    name=value pair (which may be a live session token) is never
    inspected or stored, per the Step 9.5 spec's explicit requirement.
    """
    attrs = [part.strip() for part in raw_cookie.split(";")[1:]]
    samesite = next((a.split("=", 1)[1].strip() for a in attrs if a.lower().startswith("samesite=")), None)
    return {
        "secure": any(a.lower() == "secure" for a in attrs),
        "httponly": any(a.lower() == "httponly" for a in attrs),
        "samesite": samesite,
    }


def _observe_scheme(url: str, scheme: str, seed_value: str) -> HttpObservation:
    try:
        result = http_client.fetch_url(url)
    except Exception as exc:
        return HttpObservation(scheme=scheme, requested_url=url, succeeded=False, failure_reason=str(exc))

    if isinstance(result, FetchError):
        return HttpObservation(scheme=scheme, requested_url=url, succeeded=False, failure_reason=result.reason)

    final_host = urlparse(result.final_url).hostname
    if not final_host or not is_hostname_in_scope(final_host, _seed_hostname(seed_value)):
        return HttpObservation(
            scheme=scheme,
            requested_url=url,
            succeeded=True,
            left_authorized_scope=True,
            external_redirect_host=final_host,
            final_url=result.final_url,
            redirect_count=result.redirect_count,
        )

    return _build_observation(scheme, url, result)


def _build_observation(scheme: str, url: str, result: FetchResult) -> HttpObservation:
    headers = {k.lower(): v for k, v in result.headers.items()}
    content_type = headers.get("content-type", "")
    is_html = content_type.lower().startswith("text/html")
    title = _extract_title(result.text) if is_html else None
    security_headers = {name: (name in headers) for name in _SECURITY_HEADERS}
    cookie_flags = [_parse_cookie_flags(raw) for raw in result.set_cookie_headers]
    technology_evidence = _infer_technology(headers, result.text if is_html else "")

    return HttpObservation(
        scheme=scheme,
        requested_url=url,
        succeeded=True,
        final_url=result.final_url,
        status_code=result.status_code,
        content_type=content_type or None,
        redirect_count=result.redirect_count,
        server=headers.get("server"),
        x_powered_by=headers.get("x-powered-by"),
        title=title,
        security_headers=security_headers,
        cookie_security_flags=cookie_flags,
        technology_evidence=technology_evidence,
    )


class HttpDiscoveryProvider(DiscoveryProvider):
    name = "http"
    applicable_seed_types = {AssetType.domain, AssetType.subdomain, AssetType.url}

    def discover(self, seed_value: str) -> DiscoveryProviderResult:
        if seed_value.startswith("http://") or seed_value.startswith("https://"):
            # A url-type seed: use it exactly as given, one attempt,
            # its own scheme only -- never broadened to try the other
            # scheme or a different host.
            targets = [(urlparse(seed_value).scheme, seed_value)]
        else:
            # A bare host (domain/subdomain): both schemes are
            # independently attempted -- 1 request per scheme, 2 per
            # hostname total, matching the request-policy budget.
            targets = [("https", f"https://{seed_value}/"), ("http", f"http://{seed_value}/")]

        observations = []
        for scheme, url in targets:
            try:
                observations.append(_observe_scheme(url, scheme, seed_value))
            except Exception as exc:
                # Defense in depth: _observe_scheme already catches
                # fetch_url's own exceptions, but a bug in the
                # classification logic below it must not take out the
                # other scheme's attempt or the whole provider.
                observations.append(HttpObservation(scheme=scheme, requested_url=url, succeeded=False, failure_reason=str(exc)))

        return DiscoveryProviderResult(provider=self.name, http_observations=observations)
