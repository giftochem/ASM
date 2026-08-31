"""Builds an httpx transport whose TCP connection is pinned to a specific,
already-validated IP address — this is what actually closes the DNS-
rebinding TOCTOU window in http_client.fetch(): app.scanners.net_safety
resolves and validates a hostname exactly once, and every module here
guarantees the real connection uses that exact address, never performing
a second DNS lookup that a rebinding-capable resolver could answer
differently.

TLS hostname verification is NOT weakened by this. httpcore calls
`NetworkStream.start_tls(server_hostname=...)` as a step separate from
`connect_tcp(host, port)`, and `server_hostname` is derived by httpcore
from the request's origin host (the real hostname, e.g. "example.com") —
independently of whatever `connect_tcp` actually dialed. So the
certificate is still verified against the real hostname regardless of
which IP the socket is physically connected to: pin the connection to a
wrong/mismatched IP and the handshake fails with a hostname-verification
error, exactly as it should. See tests/test_tls_pinning.py, which proves
both directions against a local self-signed server (no reliance on live
external infrastructure — a real-world experiment during development
showed a major CDN's shared anycast IP can coincidentally serve a valid
cert for an unrelated hostname via "SSL for SaaS"-style custom-hostname
features, which makes real public IPs unreliable for a deterministic
negative test).

Verified empirically against both a real HTTPS site (pinned connection
succeeds, real content retrieved, cert legitimately verified) and a local
mismatched-hostname server (pinned connection correctly fails
certificate verification) before this was written.
"""

import ssl

import httpcore
import httpx


class _PinnedNetworkBackend(httpcore.NetworkBackend):
    def __init__(self, pinned_ip: str):
        self._pinned_ip = pinned_ip
        self._delegate = httpcore.SyncBackend()

    def connect_tcp(
        self,
        host,
        port,
        timeout=None,
        local_address=None,
        socket_options=None,
    ):
        # `host` here is the real hostname from the request's origin
        # (e.g. "example.com") — deliberately ignored. Connecting to the
        # pre-validated IP instead means there is no second DNS lookup at
        # connect time for a rebinding-capable resolver to answer
        # differently from what net_safety already validated.
        return self._delegate.connect_tcp(
            self._pinned_ip,
            port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )

    def connect_unix_socket(self, path, timeout=None, socket_options=None):
        return self._delegate.connect_unix_socket(path, timeout=timeout, socket_options=socket_options)

    def sleep(self, seconds):
        self._delegate.sleep(seconds)


class _PinnedHTTPTransport(httpx.HTTPTransport):
    """Subclasses httpx.HTTPTransport purely to reuse its (otherwise
    unmodified) handle_request/close/response-streaming logic — the only
    thing overridden is which httpcore.ConnectionPool (and therefore
    which network backend) it operates against.
    """

    def __init__(self, pinned_ip: str, verify: ssl.SSLContext | str | bool = True):
        super().__init__(verify=verify)
        ssl_context = httpx.create_ssl_context(verify=verify)
        self._pool = httpcore.ConnectionPool(
            ssl_context=ssl_context,
            network_backend=_PinnedNetworkBackend(pinned_ip),
            retries=0,
        )


def build_pinned_transport(
    pinned_ip: str, verify: ssl.SSLContext | str | bool = True
) -> httpx.HTTPTransport:
    """`verify` defaults to True (system CA trust store, hostname
    verification enforced) — production code (http_client.py) never
    overrides this. The str/SSLContext forms exist only so tests can
    point at a local self-signed CA; never use them outside tests.
    """
    return _PinnedHTTPTransport(pinned_ip, verify=verify)
