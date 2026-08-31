"""Unit tests for CloudDiscoveryProvider — no real network. Same
dns.resolver.Resolver.resolve mocking as test_network_provider.py,
since CloudDiscoveryProvider composes NetworkDiscoveryProvider directly
rather than making its own queries; these tests exist to prove that
composition (delegation, rejection/failure propagation, never producing
its own candidate) is correct, not to re-test Team Cymru parsing itself
(already covered exhaustively in test_network_provider.py).
"""

import dns.exception
import dns.resolver
import dns.reversename

from app.core.enums import AssetType
from app.discovery.cloud_provider import CloudDiscoveryProvider


class _FakeRdata:
    def __init__(self, text: str):
        self._text = text

    def to_text(self) -> str:
        return self._text


class _FakeAnswer(list):
    def __init__(self, values: list[str]):
        super().__init__(_FakeRdata(v) for v in values)


def _ptr_name(ip: str) -> str:
    return str(dns.reversename.from_address(ip))


def _install_fake_resolver(monkeypatch, responses: dict[str, list[str] | Exception]):
    def _fake_resolve(self, name, rdtype, *args, **kwargs):
        key = str(name)
        if key not in responses:
            raise dns.resolver.NXDOMAIN()
        response = responses[key]
        if isinstance(response, Exception):
            raise response
        return _FakeAnswer(response)

    monkeypatch.setattr(dns.resolver.Resolver, "resolve", _fake_resolve)


def test_provider_supports_ip_address_only():
    provider = CloudDiscoveryProvider()
    assert provider.supports(AssetType.ip_address) is True
    assert provider.supports(AssetType.domain) is False
    assert provider.supports(AssetType.subdomain) is False
    assert provider.supports(AssetType.url) is False


def test_successful_discovery_produces_infrastructure_data_from_network_signals(monkeypatch):
    _install_fake_resolver(
        monkeypatch,
        {
            "8.8.8.8.origin.asn.cymru.com": ['"15169 | 8.8.8.0/24 | US | arin | 2023-12-28"'],
            "AS15169.asn.cymru.com": ['"15169 | US | arin | 2000-03-30 | GOOGLE - Google LLC, US"'],
            _ptr_name("8.8.8.8"): ["dns.google."],
        },
    )

    result = CloudDiscoveryProvider().discover("8.8.8.8")

    assert result.error is None
    assert result.candidates == []  # never creates its own candidate -- see module docstring
    infra = result.infrastructure_data
    assert infra.succeeded is True
    assert infra.rejected is False
    assert infra.asn == "AS15169"
    assert infra.asn_organization == "GOOGLE - Google LLC, US"
    assert infra.announced_prefix == "8.8.8.0/24"
    assert infra.ptr_hostname == "dns.google"


def test_private_ip_rejection_propagates_from_network_provider(monkeypatch):
    calls = []

    def _fail_if_called(self, name, rdtype, *args, **kwargs):
        calls.append(name)
        raise AssertionError("must not query DNS for an unsafe IP")

    monkeypatch.setattr(dns.resolver.Resolver, "resolve", _fail_if_called)

    result = CloudDiscoveryProvider().discover("10.0.0.5")

    assert result.error is None
    assert result.infrastructure_data.rejected is True
    assert result.infrastructure_data.rejection_reason is not None
    assert calls == []


def test_invalid_ip_string_produces_provider_error():
    result = CloudDiscoveryProvider().discover("not-an-ip-address")

    assert result.error is not None
    assert result.infrastructure_data is None


def test_total_lookup_failure_propagates_as_unsuccessful_infrastructure_data(monkeypatch):
    _install_fake_resolver(monkeypatch, {})  # everything NXDOMAINs

    result = CloudDiscoveryProvider().discover("8.8.4.4")

    assert result.error is None
    infra = result.infrastructure_data
    assert infra.succeeded is False
    assert infra.failure_reason is not None
    assert infra.asn is None


def test_partial_result_ptr_only_still_propagates(monkeypatch):
    _install_fake_resolver(monkeypatch, {_ptr_name("9.9.9.9"): ["dns9.quad9.net."]})

    result = CloudDiscoveryProvider().discover("9.9.9.9")

    infra = result.infrastructure_data
    assert infra.succeeded is True
    assert infra.asn is None
    assert infra.ptr_hostname == "dns9.quad9.net"


def test_ipv6_composition_works(monkeypatch):
    ipv6 = "2001:4860:4860::8888"
    origin_name = "8.8.8.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.6.8.4.0.6.8.4.1.0.0.2.origin6.asn.cymru.com"
    _install_fake_resolver(
        monkeypatch,
        {
            origin_name: ['"15169 | 2001:4860::/32 | US | arin | 2005-03-14"'],
            "AS15169.asn.cymru.com": ['"15169 | US | arin | 2000-03-30 | GOOGLE - Google LLC, US"'],
            _ptr_name(ipv6): ["dns.google."],
        },
    )

    result = CloudDiscoveryProvider().discover(ipv6)

    assert result.infrastructure_data.asn == "AS15169"
    assert result.infrastructure_data.announced_prefix == "2001:4860::/32"


def test_timeout_handled_as_partial_or_failed_result(monkeypatch):
    _install_fake_resolver(
        monkeypatch,
        {
            "8.8.8.8.origin.asn.cymru.com": dns.exception.Timeout(),
            _ptr_name("8.8.8.8"): dns.exception.Timeout(),
        },
    )

    result = CloudDiscoveryProvider().discover("8.8.8.8")

    assert result.error is None
    assert result.infrastructure_data.succeeded is False
