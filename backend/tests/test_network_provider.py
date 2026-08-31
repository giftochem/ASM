"""Unit tests for NetworkDiscoveryProvider — no real network.
dns.resolver.Resolver.resolve is monkeypatched, keyed by the exact
query NAME (not just record type, unlike test_dns_provider.py's
simpler by-rdtype keying) because this provider makes three distinct
queries -- origin TXT, AS-name TXT, and PTR -- that would otherwise
collide under a type-only key.
"""

import dns.exception
import dns.resolver
import dns.reversename
import pytest

from app.core.enums import AssetType, RelationshipType
from app.discovery.network_provider import NetworkDiscoveryProvider


class _FakeRdata:
    def __init__(self, text: str):
        self._text = text

    def to_text(self) -> str:
        return self._text


class _FakeAnswer(list):
    def __init__(self, values: list[str]):
        super().__init__(_FakeRdata(v) for v in values)


def _install_fake_resolver(monkeypatch, responses: dict[str, list[str] | Exception]):
    """`responses` keys are exact query names as strings (e.g.
    "8.8.8.8.origin.asn.cymru.com", "AS15169.asn.cymru.com",
    "8.8.8.8.in-addr.arpa."), mapped to a list of to_text()-shaped
    TXT/PTR strings, or an exception instance to raise. A name with no
    entry raises NXDOMAIN, matching a real "nothing here" DNS response.
    """

    def _fake_resolve(self, name, rdtype, *args, **kwargs):
        key = str(name)
        if key not in responses:
            raise dns.resolver.NXDOMAIN()
        response = responses[key]
        if isinstance(response, Exception):
            raise response
        return _FakeAnswer(response)

    monkeypatch.setattr(dns.resolver.Resolver, "resolve", _fake_resolve)


def _ptr_name(ip: str) -> str:
    return str(dns.reversename.from_address(ip))


def test_provider_supports_ip_address_only():
    provider = NetworkDiscoveryProvider()
    assert provider.supports(AssetType.ip_address) is True
    assert provider.supports(AssetType.domain) is False
    assert provider.supports(AssetType.subdomain) is False
    assert provider.supports(AssetType.url) is False


def test_valid_ipv4_extracts_asn_organization_prefix_country(monkeypatch):
    _install_fake_resolver(
        monkeypatch,
        {
            "8.8.8.8.origin.asn.cymru.com": ['"15169 | 8.8.8.0/24 | US | arin | 2023-12-28"'],
            "AS15169.asn.cymru.com": ['"15169 | US | arin | 2000-03-30 | GOOGLE - Google LLC, US"'],
            _ptr_name("8.8.8.8"): ["dns.google."],
        },
    )

    result = NetworkDiscoveryProvider().discover("8.8.8.8")

    assert result.error is None
    obs = result.network_data
    assert obs.succeeded is True
    assert obs.rejected is False
    assert obs.ip_version == 4
    assert obs.asn == "AS15169"
    assert obs.asn_organization == "GOOGLE - Google LLC, US"
    assert obs.announced_prefix == "8.8.8.0/24"
    assert obs.network_country == "US"
    assert obs.registry == "arin"
    assert obs.ptr_hostname == "dns.google"

    assert len(result.candidates) == 1
    candidate = result.candidates[0]
    assert candidate.asset_type == AssetType.asn
    assert candidate.value == "AS15169"
    assert candidate.relationship_type == RelationshipType.announced_by
    assert candidate.confidence == 0.9


def test_valid_ipv6_extracts_correctly(monkeypatch):
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

    result = NetworkDiscoveryProvider().discover(ipv6)

    obs = result.network_data
    assert obs.ip_version == 6
    assert obs.asn == "AS15169"
    assert obs.announced_prefix == "2001:4860::/32"
    assert obs.ptr_hostname == "dns.google"


def test_ptr_hostname_recorded_as_evidence_never_a_candidate(monkeypatch):
    _install_fake_resolver(
        monkeypatch,
        {
            "8.8.8.8.origin.asn.cymru.com": ['"15169 | 8.8.8.0/24 | US | arin | 2023-12-28"'],
            "AS15169.asn.cymru.com": ['"15169 | US | arin | 2000-03-30 | GOOGLE - Google LLC, US"'],
            _ptr_name("8.8.8.8"): ["dns.google."],
        },
    )

    result = NetworkDiscoveryProvider().discover("8.8.8.8")

    assert result.network_data.ptr_hostname == "dns.google"
    # Only the ASN is ever a candidate -- the PTR hostname never is.
    assert len(result.candidates) == 1
    assert all(c.asset_type != AssetType.domain and c.asset_type != AssetType.subdomain for c in result.candidates)


def test_missing_asn_but_ptr_present_partial_result(monkeypatch):
    _install_fake_resolver(
        monkeypatch,
        {
            _ptr_name("9.9.9.9"): ["dns9.quad9.net."],
        },
    )

    result = NetworkDiscoveryProvider().discover("9.9.9.9")

    obs = result.network_data
    assert obs.succeeded is True
    assert obs.asn is None
    assert obs.ptr_hostname == "dns9.quad9.net"
    assert result.candidates == []  # no ASN found -> no ASN candidate
    assert obs.confidence < 0.9  # lower confidence for a partial (PTR-only) result


def test_missing_ptr_but_asn_present_partial_result(monkeypatch):
    _install_fake_resolver(
        monkeypatch,
        {
            "8.8.8.8.origin.asn.cymru.com": ['"15169 | 8.8.8.0/24 | US | arin | 2023-12-28"'],
            "AS15169.asn.cymru.com": ['"15169 | US | arin | 2000-03-30 | GOOGLE - Google LLC, US"'],
            # No PTR entry -> NXDOMAIN.
        },
    )

    result = NetworkDiscoveryProvider().discover("8.8.8.8")

    obs = result.network_data
    assert obs.succeeded is True
    assert obs.asn == "AS15169"
    assert obs.ptr_hostname is None
    assert len(result.candidates) == 1


def test_no_data_at_all_produces_failed_result(monkeypatch):
    _install_fake_resolver(monkeypatch, {})  # everything NXDOMAINs

    result = NetworkDiscoveryProvider().discover("8.8.4.4")

    assert result.error is None  # a normal "nothing found" outcome, not a provider malfunction
    obs = result.network_data
    assert obs.succeeded is False
    assert obs.failure_reason is not None
    assert result.candidates == []


def test_malformed_origin_response_handled_cleanly(monkeypatch):
    _install_fake_resolver(
        monkeypatch,
        {
            "8.8.8.8.origin.asn.cymru.com": ['"not enough fields"'],
            _ptr_name("8.8.8.8"): ["dns.google."],
        },
    )

    result = NetworkDiscoveryProvider().discover("8.8.8.8")

    assert result.error is None
    assert result.network_data.asn is None
    assert result.network_data.ptr_hostname == "dns.google"


def test_non_numeric_asn_field_handled_cleanly(monkeypatch):
    _install_fake_resolver(
        monkeypatch,
        {
            "8.8.8.8.origin.asn.cymru.com": ['"NOT_A_NUMBER | 8.8.8.0/24 | US | arin | 2023-12-28"'],
        },
    )

    result = NetworkDiscoveryProvider().discover("8.8.8.8")

    assert result.error is None
    assert result.network_data.asn is None
    assert result.candidates == []


def test_timeout_on_origin_query_handled_cleanly(monkeypatch):
    _install_fake_resolver(
        monkeypatch,
        {
            "8.8.8.8.origin.asn.cymru.com": dns.exception.Timeout(),
            _ptr_name("8.8.8.8"): ["dns.google."],
        },
    )

    result = NetworkDiscoveryProvider().discover("8.8.8.8")

    assert result.error is None
    assert result.network_data.succeeded is True  # PTR still came through
    assert result.network_data.asn is None


def test_rate_limited_or_server_failure_handled_cleanly(monkeypatch):
    """Simulates a resolver-level failure (the closest DNS analog to an
    HTTP 429/5xx -- DNS has no status codes, but SERVFAIL/refused-style
    failures surface as resolver exceptions) -- must not crash discover().
    """
    _install_fake_resolver(
        monkeypatch,
        {
            "8.8.8.8.origin.asn.cymru.com": dns.resolver.NoNameservers(),
            _ptr_name("8.8.8.8"): dns.resolver.NoNameservers(),
        },
    )

    result = NetworkDiscoveryProvider().discover("8.8.8.8")

    assert result.error is None
    assert result.network_data.succeeded is False


@pytest.mark.parametrize(
    "unsafe_ip",
    ["127.0.0.1", "10.0.0.5", "172.16.0.5", "192.168.1.5", "169.254.1.1", "::1", "fe80::1", "224.0.0.1"],
)
def test_private_loopback_link_local_reserved_ips_rejected_without_any_query(monkeypatch, unsafe_ip):
    calls = []

    def _fail_if_called(self, name, rdtype, *args, **kwargs):
        calls.append(name)
        raise AssertionError("must not query DNS for an unsafe IP")

    monkeypatch.setattr(dns.resolver.Resolver, "resolve", _fail_if_called)

    result = NetworkDiscoveryProvider().discover(unsafe_ip)

    assert result.error is None
    assert result.network_data.rejected is True
    assert result.network_data.rejection_reason is not None
    assert calls == []  # confirms the safety check runs BEFORE any lookup


def test_documentation_range_rejected_via_real_unmocked_validation():
    """No monkeypatching at all -- proves the real, unmocked
    app.core.validation.validate_ip_address genuinely blocks a
    TEST-NET/documentation address (RFC 5737), not just a stand-in.
    """
    result = NetworkDiscoveryProvider().discover("192.0.2.1")

    assert result.network_data.rejected is True


def test_invalid_ip_string_produces_provider_error():
    result = NetworkDiscoveryProvider().discover("not-an-ip-address")

    assert result.error is not None
    assert result.network_data is None
    assert result.candidates == []


@pytest.mark.parametrize(
    "as_name,expected_provider",
    [
        ("AMAZON-02, US", "Amazon Web Services"),
        ("GOOGLE - Google LLC, US", "Google Cloud / Google"),
        ("MICROSOFT-CORP-MSN-AS-BLOCK, US", "Microsoft Azure"),
        ("CLOUDFLARENET, US", "Cloudflare"),
        ("HETZNER-AS, DE", "Hetzner"),
    ],
)
def test_cloud_provider_inference_from_well_known_as_names(monkeypatch, as_name, expected_provider):
    _install_fake_resolver(
        monkeypatch,
        {
            "8.8.8.8.origin.asn.cymru.com": ['"64500 | 8.8.8.0/24 | US | arin | 2023-12-28"'],
            "AS64500.asn.cymru.com": [f'"64500 | US | arin | 2000-03-30 | {as_name}"'],
        },
    )

    result = NetworkDiscoveryProvider().discover("8.8.8.8")

    evidence = result.network_data.cloud_provider_evidence
    assert evidence is not None
    assert evidence["provider"] == expected_provider
    assert evidence["confidence"] == 0.8
    assert "evidence" in evidence


def test_no_cloud_provider_claim_without_a_matching_signature(monkeypatch):
    _install_fake_resolver(
        monkeypatch,
        {
            "8.8.8.8.origin.asn.cymru.com": ['"64500 | 8.8.8.0/24 | US | arin | 2023-12-28"'],
            "AS64500.asn.cymru.com": ['"64500 | US | arin | 2000-03-30 | SOME-SMALL-ISP-LLC, US"'],
        },
    )

    result = NetworkDiscoveryProvider().discover("8.8.8.8")

    assert result.network_data.cloud_provider_evidence is None


def test_multi_origin_as_field_takes_first_asn(monkeypatch):
    """A prefix announced by multiple ASes (MOAS) reports several
    space-separated AS numbers in the same field -- must not crash, and
    must not guess; taking the first is a defensible, documented choice.
    """
    _install_fake_resolver(
        monkeypatch,
        {
            "8.8.8.8.origin.asn.cymru.com": ['"7018 3356 | 8.8.8.0/24 | US | arin | 2023-12-28"'],
            "AS7018.asn.cymru.com": ['"7018 | US | arin | 1998-09-25 | ATT-INTERNET4, US"'],
        },
    )

    result = NetworkDiscoveryProvider().discover("8.8.8.8")

    assert result.network_data.asn == "AS7018"
