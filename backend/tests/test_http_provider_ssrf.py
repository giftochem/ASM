"""SSRF and redirect-safety proofs for HttpDiscoveryProvider.

Most of these tests run the REAL, unmocked app.scanners.http_client.fetch_url
-> app.scanners.net_safety.resolve_and_validate chain, intercepting only at
the httpx transport layer via httpx.MockTransport — the exact same pattern
test_http_client.py already establishes ("real safety logic, mocked
transport, no real network I/O"). A numeric public IP is used as the
starting host so net_safety's DNS-resolution-and-validation step runs for
real without needing actual network access. This proves the provider
doesn't introduce a second, weaker SSRF implementation and doesn't rely
on http_client alone without adding its own scope check on top.

One test goes further and makes ZERO mocking of any kind — a real local
HTTP server on 127.0.0.1, reached through the fully real pipeline — to
prove the security boundary rejects a destination that is genuinely
listening and would otherwise respond.
"""

import http.server
import threading

import httpx
import pytest

import app.discovery.http_provider as http_provider_module
from app.discovery.http_provider import HttpDiscoveryProvider
from app.scanners.http_client import fetch_url as real_fetch_url

_PUBLIC = "93.184.216.34"


def _handler(responses: dict[str, httpx.Response]):
    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        resp = responses.get(url)
        if resp is None:
            raise AssertionError(f"unexpected request to {url} (configured: {list(responses)})")
        return resp

    return handler


def _patch_with_real_pipeline_mocked_transport(monkeypatch, responses: dict[str, httpx.Response]):
    """Routes the provider's fetch_url calls through the REAL fetch_url
    (and therefore the real net_safety validation on every hop) while
    intercepting only the httpx transport, matching test_http_client.py's
    established "real logic, fake network" pattern.
    """
    transport = httpx.MockTransport(_handler(responses))

    def _fake(url, _transport=None, *, scope):
        return real_fetch_url(url, _transport=transport, scope=scope)

    monkeypatch.setattr(http_provider_module.http_client, "fetch_url", _fake)


@pytest.mark.parametrize(
    "blocked_location",
    [
        "http://127.0.0.1/admin",
        "http://localhost/",
        "http://10.0.0.5/internal",
        "http://172.16.0.5/internal",
        "http://192.168.1.5/internal",
        "http://[::1]/",
        "http://[fe80::1]/",
        "http://169.254.169.254/latest/meta-data/",
    ],
)
def test_redirect_to_private_or_loopback_target_is_rejected_via_real_pipeline(monkeypatch, blocked_location):
    responses = {
        f"https://{_PUBLIC}/start": httpx.Response(302, headers={"Location": blocked_location}),
    }
    _patch_with_real_pipeline_mocked_transport(monkeypatch, responses)

    result = HttpDiscoveryProvider().discover(f"https://{_PUBLIC}/start")

    assert result.error is None
    assert len(result.http_observations) == 1
    obs = result.http_observations[0]
    # An IP seed's scope is that one address, so these destinations are
    # stopped by the scope check -- before they're even resolved -- and the
    # mocked transport (which fails on any unexpected request) proves none
    # was contacted. In-scope names resolving to blocked addresses are
    # covered in test_http_redirect_scope.py.
    assert obs.left_authorized_scope is True
    assert obs.status_code is None and obs.title is None and obs.server is None


def test_redirect_within_scope_is_allowed_via_real_pipeline(monkeypatch):
    responses = {
        f"https://{_PUBLIC}/start": httpx.Response(302, headers={"Location": f"https://{_PUBLIC}/final"}),
        f"https://{_PUBLIC}/final": httpx.Response(200, text="<title>Landed</title>", headers={"content-type": "text/html"}),
    }
    _patch_with_real_pipeline_mocked_transport(monkeypatch, responses)

    result = HttpDiscoveryProvider().discover(f"https://{_PUBLIC}/start")

    obs = result.http_observations[0]
    assert obs.succeeded is True
    assert obs.left_authorized_scope is False  # same host, still in scope
    assert obs.final_url == f"https://{_PUBLIC}/final"
    assert obs.title == "Landed"


def test_dns_resolving_to_private_address_is_rejected_via_real_pipeline(monkeypatch):
    """DNS-rebinding-style behavior: a hostname that itself resolves to a
    private address must be rejected before any connection, even when
    the (mocked) transport layer would otherwise happily respond.
    """
    import socket as socket_module

    def _fake_getaddrinfo(host, port, **kwargs):
        return [(socket_module.AF_INET, socket_module.SOCK_STREAM, 6, "", ("10.1.2.3", port))]

    monkeypatch.setattr(socket_module, "getaddrinfo", _fake_getaddrinfo)

    responses = {"https://internal.example.test/": httpx.Response(200, text="should never be reached")}
    _patch_with_real_pipeline_mocked_transport(monkeypatch, responses)

    result = HttpDiscoveryProvider().discover("https://internal.example.test/")

    obs = result.http_observations[0]
    assert obs.succeeded is False
    assert "blocked" in obs.failure_reason


class _RealPlainHttpServer:
    """A genuinely listening HTTP server on 127.0.0.1 — used to prove the
    security boundary rejects a target even though something real is
    there and would respond, not merely that nothing answered.
    """

    def __init__(self):
        class _Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"<title>should never be fetched</title>")

        self._server = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
        self.port = self._server.server_port
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def close(self):
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=2)


@pytest.fixture
def real_local_server():
    server = _RealPlainHttpServer()
    yield server
    server.close()


def test_real_unmocked_pipeline_rejects_loopback_even_though_a_real_server_is_listening(real_local_server):
    """No mocking anywhere in this test: the provider calls the real
    http_client.fetch_url, which calls the real net_safety.resolve_and_validate,
    which performs a real DNS/IP-literal check against 127.0.0.1 -- and
    rejects it, even though _RealPlainHttpServer genuinely is listening
    on that address and would happily respond if given the chance.
    """
    result = HttpDiscoveryProvider().discover("127.0.0.1")

    assert result.error is None
    assert len(result.http_observations) == 2  # both schemes attempted independently
    for obs in result.http_observations:
        assert obs.succeeded is False
        assert "blocked" in obs.failure_reason
        assert "loopback" in obs.failure_reason
