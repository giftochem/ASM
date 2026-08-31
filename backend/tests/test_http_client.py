"""http_client tests use a mocked httpx transport (no real network) but a
real, numeric public IP as the "safe" host, so app.scanners.net_safety's
DNS-resolution-and-validation step runs for real (no network I/O needed
for a numeric literal) — these tests exercise the actual SSRF logic, not
a stand-in for it.
"""

import httpx
import pytest

from app.config import settings
from app.scanners.http_client import FetchError, FetchResult, fetch

_PUBLIC = "93.184.216.34"


def _handler(responses: dict[str, httpx.Response | Exception]):
    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        resp = responses.get(url)
        if resp is None:
            raise AssertionError(f"unexpected request to {url} (configured: {list(responses)})")
        if isinstance(resp, Exception):
            raise resp
        return resp

    return handler


def test_successful_fetch_returns_content():
    responses = {
        f"https://{_PUBLIC}/": httpx.Response(
            200, headers={"Server": "nginx", "X-Test": "1"}, text="<html>hello</html>"
        ),
    }
    result = fetch(f"https://{_PUBLIC}/", _transport=httpx.MockTransport(_handler(responses)))
    assert isinstance(result, FetchResult)
    assert result.status_code == 200
    assert result.headers["server"] == "nginx"
    assert "hello" in result.text


def test_redirect_to_public_destination_is_followed():
    responses = {
        f"https://{_PUBLIC}/start": httpx.Response(
            302, headers={"Location": f"https://{_PUBLIC}/final"}
        ),
        f"https://{_PUBLIC}/final": httpx.Response(200, text="landed"),
    }
    result = fetch(f"https://{_PUBLIC}/start", _transport=httpx.MockTransport(_handler(responses)))
    assert isinstance(result, FetchResult)
    assert result.final_url == f"https://{_PUBLIC}/final"
    assert result.text == "landed"


@pytest.mark.parametrize(
    "blocked_location",
    [
        "http://localhost/",
        "http://127.0.0.1/admin",
        "http://10.0.0.5/internal",
        "http://169.254.169.254/latest/meta-data/",  # cloud metadata endpoint
        "http://[fc00::1]/",  # private IPv6 (ULA)
        "http://[::ffff:127.0.0.1]/",  # IPv4-mapped loopback bypass attempt
        "http://224.0.0.1/",  # multicast
    ],
)
def test_redirect_to_blocked_destination_is_not_followed(blocked_location):
    responses = {
        f"https://{_PUBLIC}/start": httpx.Response(302, headers={"Location": blocked_location}),
    }
    result = fetch(f"https://{_PUBLIC}/start", _transport=httpx.MockTransport(_handler(responses)))
    assert isinstance(result, FetchError), f"redirect to {blocked_location} should have been blocked"
    assert "blocked" in result.reason


def test_redirect_loop_is_detected():
    responses = {
        f"https://{_PUBLIC}/a": httpx.Response(302, headers={"Location": f"https://{_PUBLIC}/b"}),
        f"https://{_PUBLIC}/b": httpx.Response(302, headers={"Location": f"https://{_PUBLIC}/a"}),
    }
    result = fetch(f"https://{_PUBLIC}/a", _transport=httpx.MockTransport(_handler(responses)))
    assert isinstance(result, FetchError)
    assert "loop" in result.reason or "max_redirects" in result.reason


def test_too_many_redirects_is_rejected():
    # One more hop than max_redirects allows, each to a distinct URL so
    # this exercises the hop-count cap rather than loop detection.
    responses = {}
    for i in range(settings.max_redirects + 2):
        responses[f"https://{_PUBLIC}/hop{i}"] = httpx.Response(
            302, headers={"Location": f"https://{_PUBLIC}/hop{i + 1}"}
        )
    result = fetch(f"https://{_PUBLIC}/hop0", _transport=httpx.MockTransport(_handler(responses)))
    assert isinstance(result, FetchError)
    assert "max_redirects" in result.reason


def test_response_larger_than_cap_is_truncated(monkeypatch):
    monkeypatch.setattr(settings, "max_response_size_bytes", 100)
    big_body = "x" * 10_000
    responses = {f"https://{_PUBLIC}/big": httpx.Response(200, text=big_body)}
    result = fetch(f"https://{_PUBLIC}/big", _transport=httpx.MockTransport(_handler(responses)))
    assert isinstance(result, FetchResult)
    assert result.truncated is True
    assert len(result.text) <= 100


def test_timeout_is_reported_as_error():
    responses = {f"https://{_PUBLIC}/slow": httpx.TimeoutException("simulated timeout")}
    result = fetch(f"https://{_PUBLIC}/slow", _transport=httpx.MockTransport(_handler(responses)))
    assert isinstance(result, FetchError)
    assert "timed out" in result.reason


def test_redirect_to_non_http_scheme_is_rejected():
    responses = {
        f"https://{_PUBLIC}/start": httpx.Response(
            302, headers={"Location": "ftp://internal-ftp.example/secret"}
        ),
    }
    result = fetch(f"https://{_PUBLIC}/start", _transport=httpx.MockTransport(_handler(responses)))
    assert isinstance(result, FetchError)


def test_disallowed_port_is_rejected():
    responses = {f"https://{_PUBLIC}:9999/": httpx.Response(200, text="should not be reached")}
    result = fetch(f"https://{_PUBLIC}:9999/", _transport=httpx.MockTransport(_handler(responses)))
    assert isinstance(result, FetchError)
    assert "blocked" in result.reason
