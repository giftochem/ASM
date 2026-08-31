"""SSRF-hardened passive HTTP fetch for technology_module and headers_module.

Design constraints (see docs/README for the full rationale):
- http/https only, never anything else
- every candidate host+port is resolved and validated via net_safety
  immediately before connecting (not just at asset-creation time)
- redirects are followed manually, capped, and re-validated hop-by-hop —
  httpx's automatic redirect following is never used
- responses are streamed with a hard byte cap, regardless of what
  Content-Length claims
- TLS verification is always on; this client never disables it
- nothing here executes fetched content — callers only ever do string/
  regex matching against headers and raw text

DNS-rebinding / TOCTOU: closed, not just disclosed. Every connection is
made through app.scanners.pinned_transport, which forces the TCP layer to
use the exact IP address net_safety already resolved and validated —
httpx/httpcore never get a chance to re-resolve the hostname themselves
and possibly get a different (rebound) answer. TLS hostname verification
is unaffected by this: see pinned_transport's module docstring for why,
and tests/test_tls_pinning.py for proof in both directions.
"""

from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

import httpx

from app.config import settings
from app.scanners.net_safety import SafeTarget, UnsafeTarget, resolve_and_validate
from app.scanners.pinned_transport import build_pinned_transport

_USER_AGENT = "ASM-Scanner/1.0 (+authorized-attack-surface-scan)"


@dataclass
class FetchResult:
    final_url: str
    status_code: int
    headers: dict[str, str]
    text: str
    truncated: bool
    # Additive (Step 9.5) -- existing callers (headers_module,
    # technology_module) don't reference either field, so this is fully
    # backward compatible.
    redirect_count: int = 0
    # dict(response.headers) above collapses repeated headers to their
    # last value, which is lossy for Set-Cookie specifically (a response
    # can legitimately set several cookies). get_list preserves all of
    # them for callers that need to inspect cookie attributes.
    set_cookie_headers: list[str] = field(default_factory=list)


@dataclass
class FetchError:
    reason: str


def _candidate_urls(target: str) -> list[str]:
    if target.startswith("http://") or target.startswith("https://"):
        return [target]
    return [f"https://{target}/", f"http://{target}/"]


def _validate_url_target(url: str) -> SafeTarget | UnsafeTarget:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return UnsafeTarget(f"unsupported scheme '{parsed.scheme}'")
    if not parsed.hostname:
        return UnsafeTarget(f"no host in URL '{url}'")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return resolve_and_validate(parsed.hostname, port)


def _read_capped(response: httpx.Response) -> tuple[str, bool]:
    """Streams the body, stopping at max_response_size_bytes regardless of
    what Content-Length claims (a malicious/misconfigured server can lie).
    """
    total = 0
    chunks: list[bytes] = []
    truncated = False
    for chunk in response.iter_bytes():
        total += len(chunk)
        if total > settings.max_response_size_bytes:
            truncated = True
            break
        chunks.append(chunk)
    body = b"".join(chunks)
    return body.decode(response.encoding or "utf-8", errors="replace"), truncated


def fetch_url(
    url: str, _transport: httpx.BaseTransport | None = None
) -> FetchResult | FetchError:
    """Fetches exactly one URL, as given, with no scheme fallback —
    unlike `fetch()` below, this never substitutes or tries a second
    scheme. Public (Step 9.5) so a caller that needs independent
    per-scheme results (e.g. the HTTP discovery provider, which reports
    "is HTTPS reachable" and "is HTTP reachable" as two separate
    signals rather than "the first one that worked") can call it
    directly instead of going through `fetch()`'s first-success-wins
    behavior. Was private (`_fetch_one`) with `fetch()` as its only
    caller; renaming it is a pure rename, not a behavior change.

    `_transport` is a testability seam only — production code never
    passes it, so httpx uses its normal real transport. Tests inject an
    httpx.MockTransport to avoid making real network calls while still
    exercising the full redirect/validation/streaming logic below.
    """
    timeout = httpx.Timeout(
        connect=settings.http_connect_timeout_seconds,
        read=settings.http_read_timeout_seconds,
        write=settings.http_read_timeout_seconds,
        pool=settings.http_connect_timeout_seconds,
    )

    current_url = url
    seen_urls = set()
    redirect_count = 0
    for _ in range(settings.max_redirects + 1):
        validation = _validate_url_target(current_url)
        if isinstance(validation, UnsafeTarget):
            return FetchError(f"blocked target '{current_url}': {validation.reason}")
        if current_url in seen_urls:
            return FetchError(f"redirect loop detected at '{current_url}'")
        seen_urls.add(current_url)

        # Pin this hop's connection to the exact IP just validated, rather
        # than letting httpx resolve the hostname itself a second time —
        # that second, unvalidated resolution is precisely the TOCTOU gap
        # a DNS-rebinding attacker would exploit. `_transport` (test-only)
        # bypasses pinning so MockTransport-based tests can still exercise
        # the redirect/timeout/size-cap logic here without real sockets.
        transport = _transport or build_pinned_transport(validation.resolved_ips[0])

        try:
            with httpx.Client(
                follow_redirects=False, timeout=timeout, verify=True, transport=transport
            ) as client:
                with client.stream(
                    "GET", current_url, headers={"User-Agent": _USER_AGENT}
                ) as response:
                    if response.is_redirect:
                        location = response.headers.get("location")
                        if not location:
                            return FetchError(f"redirect from '{current_url}' had no Location header")
                        current_url = urljoin(current_url, location)
                        redirect_count += 1
                        continue

                    text, truncated = _read_capped(response)
                    return FetchResult(
                        final_url=current_url,
                        status_code=response.status_code,
                        headers=dict(response.headers),
                        text=text,
                        truncated=truncated,
                        redirect_count=redirect_count,
                        set_cookie_headers=response.headers.get_list("set-cookie"),
                    )
        except httpx.TimeoutException as exc:
            return FetchError(f"timed out fetching '{current_url}': {exc}")
        except httpx.HTTPError as exc:
            return FetchError(f"request to '{current_url}' failed: {exc}")

    return FetchError(f"exceeded max_redirects={settings.max_redirects} starting from '{url}'")


def fetch(target: str, _transport: httpx.BaseTransport | None = None) -> FetchResult | FetchError:
    """Fetches `target`, which may be a bare host (domain/subdomain/
    ip_address asset value — https tried first, http as fallback) or a
    full http(s) URL (url asset value, used as-is). `_transport` is a
    test-only seam, see fetch_url.
    """
    errors: list[str] = []
    for candidate in _candidate_urls(target):
        result = fetch_url(candidate, _transport)
        if isinstance(result, FetchResult):
            return result
        errors.append(result.reason)
    return FetchError("; ".join(errors) if errors else f"no candidate URLs for '{target}'")
