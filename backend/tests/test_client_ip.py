"""get_client_ip() must default to "trust nothing" — X-Forwarded-For is
only honored from a peer explicitly listed in settings.trusted_proxy_ips.
This is what keeps the header safe to introduce ahead of nginx actually
being deployed: with the default empty allowlist, behavior is identical
to the pre-Phase-3b `request.client.host` fallback.
"""

from starlette.requests import Request

from app.config import settings
from app.core.client_ip import get_client_ip


def _make_request(client_host: str | None, headers: dict[str, str] | None = None) -> Request:
    scope = {
        "type": "http",
        "client": (client_host, 12345) if client_host else None,
        "headers": [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()],
    }
    return Request(scope)


def test_untrusted_peer_forwarded_header_is_ignored(monkeypatch):
    monkeypatch.setattr(type(settings), "trusted_proxy_ips", property(lambda self: set()))
    request = _make_request("203.0.113.5", {"X-Forwarded-For": "9.9.9.9"})
    assert get_client_ip(request) == "203.0.113.5"


def test_trusted_peer_forwarded_header_is_honored(monkeypatch):
    monkeypatch.setattr(type(settings), "trusted_proxy_ips", property(lambda self: {"172.20.0.5"}))
    request = _make_request("172.20.0.5", {"X-Forwarded-For": "9.9.9.9"})
    assert get_client_ip(request) == "9.9.9.9"


def test_trusted_peer_takes_first_hop_of_chain(monkeypatch):
    monkeypatch.setattr(type(settings), "trusted_proxy_ips", property(lambda self: {"172.20.0.5"}))
    request = _make_request("172.20.0.5", {"X-Forwarded-For": "9.9.9.9, 172.20.0.5"})
    assert get_client_ip(request) == "9.9.9.9"


def test_trusted_peer_without_header_falls_back_to_direct_peer(monkeypatch):
    monkeypatch.setattr(type(settings), "trusted_proxy_ips", property(lambda self: {"172.20.0.5"}))
    request = _make_request("172.20.0.5")
    assert get_client_ip(request) == "172.20.0.5"


def test_trusted_peer_with_empty_header_falls_back_to_direct_peer(monkeypatch):
    monkeypatch.setattr(type(settings), "trusted_proxy_ips", property(lambda self: {"172.20.0.5"}))
    request = _make_request("172.20.0.5", {"X-Forwarded-For": ""})
    assert get_client_ip(request) == "172.20.0.5"


def test_no_client_at_all_returns_none():
    request = _make_request(None)
    assert get_client_ip(request) is None


def test_default_trusted_proxy_ips_is_empty():
    """Guards the safe default itself, not just the logic around it —
    if this ever silently changes to a non-empty default, every request
    to the app (still directly reachable pre-nginx) would start trusting
    a spoofable header.
    """
    assert settings.trusted_proxy_ips == set()
