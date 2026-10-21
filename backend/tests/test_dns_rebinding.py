"""Deterministic proof that http_client.fetch() cannot be tricked by a DNS
answer changing between validation and connection (the classic DNS-
rebinding SSRF bypass).

Simulates rebinding by making socket.getaddrinfo return a SAFE public
address on the first call for a given hostname (what net_safety validates
and pins to) and an UNSAFE private address on any subsequent call for
that hostname (what a resolver could return if asked again a moment
later, and what a naive non-pinned implementation would end up
connecting to). The actual TCP dial is captured (not really performed),
and must always match the address that was validated — proving there is
no window in which a second, unvalidated resolution can influence where
the connection actually goes.
"""

import socket

from app.scanners import http_client

_SAFE_IP = "93.184.216.34"
_REBOUND_UNSAFE_IP = "10.0.0.99"
_TARGET_HOST = "rebinding-target.example"


def test_connection_always_targets_the_validated_ip_not_a_rebound_one(monkeypatch):
    getaddrinfo_calls = {"n": 0}
    real_getaddrinfo = socket.getaddrinfo

    def rebinding_getaddrinfo(host, port, *args, **kwargs):
        if host != _TARGET_HOST:
            return real_getaddrinfo(host, port, *args, **kwargs)
        getaddrinfo_calls["n"] += 1
        # First lookup (net_safety's validation) answers safe; every
        # subsequent lookup for the same host answers with a private
        # address -- simulating a rebinding-capable resolver changing its
        # answer moments later.
        ip = _SAFE_IP if getaddrinfo_calls["n"] == 1 else _REBOUND_UNSAFE_IP
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, port))]

    monkeypatch.setattr(socket, "getaddrinfo", rebinding_getaddrinfo)

    dialed_addresses = []

    def capturing_create_connection(address, *args, **kwargs):
        dialed_addresses.append(address)
        # No real network double needed: we only care what address the
        # connection layer was asked to dial, not what a server answers.
        raise ConnectionRefusedError("test double: not actually connecting")

    monkeypatch.setattr(socket, "create_connection", capturing_create_connection)

    # A single, fully-qualified URL target means exactly one candidate is
    # tried (see http_client._candidate_urls) -- keeps this test focused
    # on the one thing it's proving, rather than also exercising the
    # separate https-then-http fallback behavior.
    result = http_client.fetch(f"https://{_TARGET_HOST}/", scope=http_client.RequestScope.for_target(_TARGET_HOST))

    assert isinstance(result, http_client.FetchError)
    assert getaddrinfo_calls["n"] == 1, (
        "resolve_and_validate should be the only DNS lookup performed for "
        "this hop -- a second lookup here is exactly the TOCTOU window "
        "DNS rebinding exploits"
    )
    assert len(dialed_addresses) == 1
    dialed_ip = dialed_addresses[0][0]
    assert dialed_ip == _SAFE_IP, (
        f"connection was attempted to {dialed_ip}, not the validated "
        f"address {_SAFE_IP} -- a rebound DNS answer reached the socket layer"
    )
    assert dialed_ip != _REBOUND_UNSAFE_IP


def test_rebound_answer_alone_would_have_been_rejected_by_validation(monkeypatch):
    """Companion check: the "rebound" address used above is independently
    confirmed private/blocked -- so if pinning were ever removed and a
    second resolution reintroduced, this specific rebind would (at least)
    still be caught by net_safety's own IP-safety checks. This is a
    defense-in-depth note, not a substitute for the pinning proof above:
    the whole point of DNS rebinding is that the attacker fully controls
    DNS and could just as easily rebind to a plausible-looking public IP
    that routes to an internal network via other means (e.g. cloud
    metadata endpoints are link-local, which validation does catch, but
    more exotic network-level redirects are not something DNS-level
    validation alone can ever fully rule out).
    """
    from app.scanners.net_safety import UnsafeTarget, resolve_and_validate

    real_getaddrinfo = socket.getaddrinfo
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda host, port, *a, **kw: [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (_REBOUND_UNSAFE_IP, port))
        ]
        if host == _TARGET_HOST
        else real_getaddrinfo(host, port, *a, **kw),
    )

    result = resolve_and_validate(_TARGET_HOST, 443)
    assert isinstance(result, UnsafeTarget)
