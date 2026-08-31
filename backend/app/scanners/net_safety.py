"""SSRF primitives: resolve a hostname and decide whether every address it
resolves to is safe to connect our own outbound requests to.

Used by app.scanners.http_client (and available for any future module that
opens its own direct socket to a target, e.g. a hardened version of
ssl_module). Deliberately does not rely on hostname string checks alone —
a hostname is only as trustworthy as what it resolves to *right now*, and
DNS is attacker-influenced input for a tool like this.
"""

import ipaddress
import socket
from dataclasses import dataclass

from app.config import settings

_BLOCKED_HOSTNAME_LITERALS = {"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"}


@dataclass
class UnsafeTarget:
    reason: str


@dataclass
class SafeTarget:
    host: str
    port: int
    resolved_ips: list[str]


def _is_blocked_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:
    """Returns a reason string if `ip` must be blocked, else None.

    Handles IPv4-mapped IPv6 addresses explicitly (e.g. ::ffff:127.0.0.1)
    — checking .is_loopback/.is_private on the IPv6 form alone does NOT
    catch these; RFC 4291 semantics for IPv6Address only recognize ::1 as
    loopback, so an embedded IPv4 loopback/private address must be
    unwrapped and checked in its own right. This is a known real-world
    filter-bypass technique, not a hypothetical edge case.
    """
    candidates = [ip]
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        candidates.append(ip.ipv4_mapped)

    for candidate in candidates:
        if candidate.is_loopback:
            return f"{candidate} is a loopback address"
        if candidate.is_private:
            return f"{candidate} is a private address"
        if candidate.is_link_local:
            return f"{candidate} is a link-local address"
        if candidate.is_multicast:
            return f"{candidate} is a multicast address"
        if candidate.is_reserved:
            return f"{candidate} is a reserved address"
        if candidate.is_unspecified:
            return f"{candidate} is the unspecified address"
    return None


def resolve_and_validate(host: str, port: int) -> SafeTarget | UnsafeTarget:
    """Resolves `host` (all A + AAAA records, not just the first) and
    validates every resolved address plus the destination port. Rejects
    the whole hostname if even one resolved address is unsafe — with
    multiple A/AAAA records, the client (or an attacker-controlled
    resolver) decides which one actually gets used, so a single bad
    record makes the hostname untrustworthy as a whole.
    """
    if host.strip().lower() in _BLOCKED_HOSTNAME_LITERALS:
        return UnsafeTarget(f"'{host}' is a blocked hostname literal")

    if port not in settings.allowed_scan_ports:
        return UnsafeTarget(
            f"port {port} is not in the allowed scan port set {sorted(settings.allowed_scan_ports)}"
        )

    try:
        addrinfo = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        return UnsafeTarget(f"DNS resolution failed for '{host}': {exc}")

    resolved_ips: list[str] = []
    for family, _, _, _, sockaddr in addrinfo:
        raw_ip = sockaddr[0]
        # IPv6 sockaddr may carry a zone/scope id (e.g. "fe80::1%eth0"),
        # which ipaddress.ip_address() cannot parse — strip it for
        # validation purposes; scoped/link-local addresses are rejected by
        # is_link_local regardless of the zone id.
        ip_text = raw_ip.split("%", 1)[0]
        try:
            ip = ipaddress.ip_address(ip_text)
        except ValueError:
            return UnsafeTarget(f"could not parse resolved address '{raw_ip}' for '{host}'")

        reason = _is_blocked_ip(ip)
        if reason:
            return UnsafeTarget(f"'{host}' resolves to a blocked address: {reason}")
        resolved_ips.append(str(ip))

    if not resolved_ips:
        return UnsafeTarget(f"DNS resolution for '{host}' returned no usable addresses")

    return SafeTarget(host=host, port=port, resolved_ips=resolved_ips)
