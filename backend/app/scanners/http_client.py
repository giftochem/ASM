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

Authorization scope: every fetch carries a required RequestScope — the
hosts the user authorized for this target. The initial URL and every
redirect hop are checked against it BEFORE the destination is resolved,
connected to or requested; an out-of-scope hop ends the fetch with a
ScopeRejection, so an unauthorized host is never contacted (not even a
DNS lookup), and a chain can't bounce through one. Each hop is parsed
once by httpx, and that same parsed URL is what's scope-checked,
resolved and requested, so no second URL parser can disagree about the
host. There is no unrestricted scope: `scope` has no default.
"""

import ipaddress
from dataclasses import dataclass, field
from urllib.parse import urljoin

import httpx

from app.config import settings
from app.core.validation import is_hostname_in_scope
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


def _normalize_host(host: str) -> str:
    return host.strip().rstrip(".").lower()


def _canonical_ip(host: str) -> str | None:
    """The canonical form of `host` if it is a standard IP literal, else
    None. Strict on purpose: decimal (2130706433), hex (0x7f.1) or
    shortened (127.1) spellings are not IP literals here, so they can
    never match an IP scope -- and are not a hostname scope's either."""
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        return None


@dataclass(frozen=True)
class RequestScope:
    """Which hosts a fetch may contact on behalf of one authorized target.

    - Hostname target (domain/subdomain, or a url's host): that host and
      its subdomains, by app.core.validation.is_hostname_in_scope -- the
      rule discovery applies everywhere else. Compared in ASCII (IDNA)
      form, case-insensitively, ignoring a trailing dot, so a Unicode
      look-alike is a different host. An IP literal is never in scope.
    - IP target: that exact address only, compared canonically; any other
      address, any hostname and any alternate IP spelling is out of scope.

    Build it with for_target(); a bare RequestScope() permits nothing.
    """

    hostname: str | None = None
    ip: str | None = None

    @classmethod
    def for_target(cls, target: str) -> "RequestScope":
        """The scope of an asset value: a bare host or IP, or an http(s)
        URL. Raises ValueError when there's no usable host."""
        if target.startswith(("http://", "https://")):
            host = httpx.URL(target).raw_host.decode("ascii")
        else:
            host = target
        host = _normalize_host(host)
        if not host:
            raise ValueError(f"no host in target '{target}'")
        ip = _canonical_ip(host)
        if ip is not None:
            return cls(ip=ip)
        return cls(hostname=host.encode("idna").decode("ascii"))

    def permits(self, host: str) -> bool:
        """`host` is httpx's ASCII host (URL.raw_host) for one hop."""
        host = _normalize_host(host)
        if not host:
            return False
        ip = _canonical_ip(host)
        if self.ip is not None:
            return ip == self.ip
        if self.hostname is None or ip is not None:
            return False
        return is_hostname_in_scope(host, self.hostname)


@dataclass
class ScopeRejection:
    """A hop's destination was outside the RequestScope. Returned BEFORE
    that destination was resolved or contacted. `url` is the rejected
    destination without credentials, query or fragment."""

    url: str
    host: str
    redirect_count: int

    @property
    def reason(self) -> str:
        return f"'{self.host}' is outside the target's authorized scope; it was not contacted"


def _display_url(target: httpx.URL) -> str:
    host = target.raw_host.decode("ascii", errors="replace")
    if ":" in host:
        host = f"[{host}]"
    port = f":{target.port}" if target.port is not None else ""
    return f"{target.scheme}://{host}{port}{target.path}"


def _candidate_urls(target: str) -> list[str]:
    if target.startswith("http://") or target.startswith("https://"):
        return [target]
    return [f"https://{target}/", f"http://{target}/"]


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
    url: str, _transport: httpx.BaseTransport | None = None, *, scope: RequestScope
) -> FetchResult | FetchError | ScopeRejection:
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

    `scope` is required: every hop -- the initial URL included -- must be
    inside it, checked before that hop is resolved or contacted (see the
    module docstring). An out-of-scope hop returns a ScopeRejection.
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
        # Parsed once, by the client that will send it: the host checked
        # below is exactly the host resolved, connected to and requested.
        try:
            target = httpx.URL(current_url)
            host = target.raw_host.decode("ascii")
        except (httpx.InvalidURL, UnicodeError, ValueError) as exc:
            return FetchError(f"blocked target: invalid URL ({exc})")
        if target.scheme not in ("http", "https"):
            return FetchError(f"blocked target '{_display_url(target)}': unsupported scheme '{target.scheme}'")
        if not host:
            return FetchError(f"blocked target '{_display_url(target)}': no host in URL")
        # Authorization scope first: an out-of-scope destination is never
        # resolved, connected to or requested.
        if not scope.permits(host):
            return ScopeRejection(url=_display_url(target), host=_normalize_host(host), redirect_count=redirect_count)
        if target.userinfo:
            return FetchError(f"blocked target '{_display_url(target)}': URLs carrying credentials are not followed")
        validation: SafeTarget | UnsafeTarget = resolve_and_validate(
            host, target.port or (443 if target.scheme == "https" else 80)
        )
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
                    "GET", target, headers={"User-Agent": _USER_AGENT}
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


def fetch(
    target: str, _transport: httpx.BaseTransport | None = None, *, scope: RequestScope
) -> FetchResult | FetchError | ScopeRejection:
    """Fetches `target`, which may be a bare host (domain/subdomain/
    ip_address asset value — https tried first, http as fallback) or a
    full http(s) URL (url asset value, used as-is). `_transport` is a
    test-only seam, see fetch_url. `scope` is required, as for fetch_url
    (callers pass RequestScope.for_target(target)). When no candidate
    succeeds and one was stopped for leaving scope, that ScopeRejection
    is returned, so callers can report it as such.
    """
    errors: list[str] = []
    rejection: ScopeRejection | None = None
    for candidate in _candidate_urls(target):
        result = fetch_url(candidate, _transport, scope=scope)
        if isinstance(result, FetchResult):
            return result
        if isinstance(result, ScopeRejection):
            rejection = rejection or result
            continue
        errors.append(result.reason)
    if rejection is not None:
        return rejection
    return FetchError("; ".join(errors) if errors else f"no candidate URLs for '{target}'")
