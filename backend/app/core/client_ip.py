"""Client-IP extraction used by both rate limiting and audit logging.

Both previously used `request.client.host` directly — the raw TCP peer
address. That's correct with no reverse proxy in front of the app, but
becomes wrong the moment one is added (Phase 3b's nginx): every request's
peer becomes the proxy's own address, collapsing rate limiting to one
shared bucket for every real user and making every audit log entry's
`ip_address` record the proxy instead of the actual client.

`X-Forwarded-For` fixes that — but only if trusted selectively. Trusting
it unconditionally lets ANY caller spoof their apparent IP just by
setting the header themselves, which would make rate limiting and audit
logging actively worse than not having the fix at all (an attacker can
now claim to be any IP they like). settings.trusted_proxy_ips gates this:
the header is only honored when the immediate TCP peer is itself a known,
trusted proxy — everyone else's X-Forwarded-For claim is ignored.
"""

from fastapi import Request

from app.config import settings


def get_client_ip(request: Request) -> str | None:
    direct_peer = request.client.host if request.client else None

    if direct_peer and direct_peer in settings.trusted_proxy_ips:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            # The header can carry a chain (client, proxy1, proxy2, ...)
            # if multiple proxies are involved; the first entry is the
            # original client as seen by the nearest trusted hop.
            first_hop = forwarded.split(",")[0].strip()
            if first_hop:
                return first_hop

    return direct_peer
