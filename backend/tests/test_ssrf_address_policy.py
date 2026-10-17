"""Outbound address policy. RFC 6598 shared address space (CGNAT,
100.64.0.0/10 -- including 100.100.100.200, a cloud metadata address) is
blocked alongside private, loopback, link-local and IPv4-mapped forms, in
both places that decide it -- asset/target validation (app.core.validation)
and connection-time checks (app.scanners.net_safety) -- and every outbound
consumer applies it: HTTP discovery, certificate discovery, SSL scanning,
port scanning, the HTTP-based scanner modules, and the network provider's
seed check. Public IPv4 and IPv6 targets stay reachable.

Hermetic: DNS answers are faked via socket.getaddrinfo and every TCP dial
is intercepted (recorded, then refused) -- nothing reaches a network.
"""

import socket

import pytest

from app.core.enums import AssetType
from app.core.exceptions import InvalidTargetError
from app.core.validation import SHARED_ADDRESS_SPACE, normalize_asset_value
from app.discovery.certificate_provider import CertificateDiscoveryProvider
from app.discovery.http_provider import HttpDiscoveryProvider
from app.discovery.network_provider import NetworkDiscoveryProvider
from app.scanners import http_client, net_safety
from app.scanners.headers_module import HeadersModule
from app.scanners.port_scanner_module import PortScannerModule
from app.scanners.ssl_module import SSLModule
from app.scanners.technology_module import TechnologyModule

CGNAT = ["100.64.0.0", "100.64.0.1", "100.100.100.200", "100.127.255.255"]
PRIVATE_AND_LOOPBACK = ["10.0.0.1", "172.16.0.1", "192.168.0.1", "127.0.0.1", "169.254.169.254", "::1", "fe80::1"]
IPV4_MAPPED = ["::ffff:100.100.100.200", "::ffff:10.0.0.1", "::ffff:127.0.0.1"]
# Other IPv6 forms embedding the metadata address: IPv4-compatible and NAT64.
OTHER_EMBEDDED_IPV4 = ["::100.100.100.200", "64:ff9b::6464:64c8"]
BLOCKED = CGNAT + PRIVATE_AND_LOOPBACK + IPV4_MAPPED + OTHER_EMBEDDED_IPV4
# 100.63.255.255 and 100.128.0.0 sit just outside 100.64.0.0/10 -- public.
PUBLIC_IPV4 = ["93.184.216.34", "1.1.1.1", "100.63.255.255", "100.128.0.0"]
PUBLIC_IPV6 = ["2606:4700:4700::1111", "2001:4860:4860::8888"]

_METADATA_IP = "100.100.100.200"
_HOST = "target.example"


def _fake_dns(monkeypatch, answers: dict[str, list[str]]) -> None:
    passthrough = socket.getaddrinfo

    def fake_getaddrinfo(host, port, *args, **kwargs):
        if host not in answers:
            return passthrough(host, port, *args, **kwargs)
        results = []
        for ip in answers[host]:
            if ":" in ip:
                results.append((socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, port, 0, 0)))
            else:
                results.append((socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, port)))
        return results

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)


@pytest.fixture
def dials(monkeypatch):
    """Every TCP dial -- ssl/certificate/port scanner directly, HTTP via
    httpcore's sync backend -- goes through socket.create_connection;
    recorded here and refused, so nothing is ever contacted."""
    attempted: list[tuple] = []

    def refusing_create_connection(address, *args, **kwargs):
        attempted.append(tuple(address[:2]))
        raise ConnectionRefusedError("test double: not actually connecting")

    monkeypatch.setattr(socket, "create_connection", refusing_create_connection)
    return attempted


# --- connection-time policy (net_safety) ------------------------------------


def test_shared_address_space_is_exactly_rfc_6598():
    assert str(SHARED_ADDRESS_SPACE) == "100.64.0.0/10"


@pytest.mark.parametrize("blocked_ip", BLOCKED)
def test_blocked_addresses_are_refused_at_connection_time(monkeypatch, blocked_ip):
    _fake_dns(monkeypatch, {_HOST: [blocked_ip]})

    result = net_safety.resolve_and_validate(_HOST, 443)

    assert isinstance(result, net_safety.UnsafeTarget)


@pytest.mark.parametrize("cgnat_ip", CGNAT)
def test_cgnat_refusal_names_the_shared_address_space(monkeypatch, cgnat_ip):
    _fake_dns(monkeypatch, {_HOST: [cgnat_ip]})

    result = net_safety.resolve_and_validate(_HOST, 443)

    assert isinstance(result, net_safety.UnsafeTarget)
    assert "shared address space" in result.reason


@pytest.mark.parametrize("public_ip", PUBLIC_IPV4 + PUBLIC_IPV6)
def test_public_ipv4_and_ipv6_targets_are_allowed(monkeypatch, public_ip):
    _fake_dns(monkeypatch, {_HOST: [public_ip]})

    result = net_safety.resolve_and_validate(_HOST, 443)

    assert isinstance(result, net_safety.SafeTarget)
    assert result.resolved_ips == [public_ip]


@pytest.mark.parametrize(
    ("answers", "allowed"),
    [
        (["93.184.216.34", _METADATA_IP], False),
        ([_METADATA_IP, "93.184.216.34"], False),
        (["2606:4700:4700::1111", "::ffff:127.0.0.1"], False),
        (["1.1.1.1", "10.0.0.1"], False),
        (["93.184.216.34", "2606:4700:4700::1111"], True),
    ],
)
def test_mixed_dns_answers_are_refused_if_any_address_is_blocked(monkeypatch, answers, allowed):
    _fake_dns(monkeypatch, {_HOST: answers})

    result = net_safety.resolve_and_validate(_HOST, 443)

    if allowed:
        assert isinstance(result, net_safety.SafeTarget)
        assert result.resolved_ips == answers
    else:
        assert isinstance(result, net_safety.UnsafeTarget)


# --- asset/target validation (app.core.validation) ---------------------------


@pytest.mark.parametrize("blocked_ip", BLOCKED)
def test_blocked_ip_addresses_cannot_become_assets(blocked_ip):
    with pytest.raises(InvalidTargetError):
        normalize_asset_value(AssetType.ip_address, blocked_ip, 20)


@pytest.mark.parametrize("mapped", ["::ffff:100.100.100.200", "::ffff:1.1.1.1"])
def test_ipv4_mapped_notation_is_never_an_asset_value(mapped):
    """Even a mapped PUBLIC address is refused at the asset layer -- it's
    the IPv4 address in IPv6 notation, and Python classifies it by the
    embedded IPv4, which is what let the mapped CGNAT form through. (At
    connection time a DNS answer of ::ffff:<public> is still allowed: that
    really is a connection to a public address.)"""
    with pytest.raises(InvalidTargetError, match="IPv4-mapped"):
        normalize_asset_value(AssetType.ip_address, mapped, 20)


def test_ipv4_mapped_ranges_cannot_become_assets():
    with pytest.raises(InvalidTargetError, match="IPv4-mapped"):
        normalize_asset_value(AssetType.ip_range, "::ffff:6440:0/112", 20)  # == ::ffff:100.64.0.0/112


@pytest.mark.parametrize("public_ip", PUBLIC_IPV4 + PUBLIC_IPV6)
def test_public_ip_addresses_can_become_assets(public_ip):
    assert normalize_asset_value(AssetType.ip_address, public_ip, 20) == public_ip


@pytest.mark.parametrize("cgnat_range", ["100.64.0.0/24", "100.100.100.0/24", "100.127.255.0/24"])
def test_cgnat_ranges_cannot_become_assets(cgnat_range):
    with pytest.raises(InvalidTargetError, match="CGNAT"):
        normalize_asset_value(AssetType.ip_range, cgnat_range, 20)


def test_ranges_adjacent_to_cgnat_are_still_allowed():
    assert normalize_asset_value(AssetType.ip_range, "100.128.0.0/24", 20) == "100.128.0.0/24"
    assert normalize_asset_value(AssetType.ip_range, "100.63.255.0/24", 20) == "100.63.255.0/24"


@pytest.mark.parametrize("url", [f"http://{_METADATA_IP}/", "https://[::ffff:100.100.100.200]/latest/meta-data/"])
def test_cgnat_url_literals_cannot_become_assets(url):
    with pytest.raises(InvalidTargetError):
        normalize_asset_value(AssetType.url, url, 20)


def test_cgnat_asset_creation_is_rejected_through_the_api(client, register_user):
    headers = register_user(email="cgnat-asset@example.com")

    resp = client.post("/assets", json={"asset_type": "ip_address", "value": _METADATA_IP}, headers=headers)

    assert resp.status_code == 422
    assert "CGNAT" in resp.text


# --- every outbound consumer applies the policy -------------------------------


def _http_fetch_url(host):
    return http_client.fetch_url(f"https://{host}/").reason


def _http_discovery(host):
    observations = HttpDiscoveryProvider().discover(host).http_observations
    assert observations and all(not observation.succeeded for observation in observations)
    return " | ".join(observation.failure_reason for observation in observations)


def _headers_scan(host):
    return HeadersModule().run(host).error


def _technology_scan(host):
    return TechnologyModule().run(host).error


def _certificate_discovery(host):
    return CertificateDiscoveryProvider().discover(host).error


def _ssl_scan(host):
    return SSLModule().run(host).error


HOSTNAME_CONSUMERS = {
    "http_client.fetch_url": _http_fetch_url,
    "http discovery": _http_discovery,
    "headers scan": _headers_scan,
    "technology scan": _technology_scan,
    "certificate discovery": _certificate_discovery,
    "ssl scan": _ssl_scan,
}


@pytest.mark.parametrize("consumer", sorted(HOSTNAME_CONSUMERS))
@pytest.mark.parametrize("cgnat_answer", [_METADATA_IP, "::ffff:100.100.100.200"])
def test_every_hostname_consumer_refuses_cgnat_without_dialing(monkeypatch, dials, consumer, cgnat_answer):
    _fake_dns(monkeypatch, {_HOST: [cgnat_answer]})

    refusal = HOSTNAME_CONSUMERS[consumer](_HOST)

    assert refusal and "resolves to a blocked address" in refusal
    if cgnat_answer == _METADATA_IP:
        # Asserted only for the plain form: which rule names the mapped
        # form first depends on how the running Python classifies
        # IPv4-mapped addresses -- refused either way, as asserted above.
        assert "shared address space" in refusal
    assert dials == []


@pytest.mark.parametrize("consumer", sorted(HOSTNAME_CONSUMERS))
def test_every_hostname_consumer_refuses_a_mixed_answer_without_dialing(monkeypatch, dials, consumer):
    _fake_dns(monkeypatch, {_HOST: ["93.184.216.34", _METADATA_IP]})

    refusal = HOSTNAME_CONSUMERS[consumer](_HOST)

    assert refusal and "shared address space" in refusal
    assert dials == []


@pytest.mark.parametrize("target", [_METADATA_IP, "::ffff:100.100.100.200", "10.0.0.1", "127.0.0.1"])
def test_port_scanner_refuses_blocked_targets_without_dialing(dials, target):
    result = PortScannerModule().run(target)

    assert result.error is not None and "blocked target" in result.error
    assert dials == []


@pytest.mark.parametrize("seed", [_METADATA_IP, "100.64.0.1"])
def test_network_provider_rejects_cgnat_seeds_before_any_lookup(seed):
    """The session network guard fails this test if any DNS lookup leaks."""
    result = NetworkDiscoveryProvider().discover(seed)

    assert result.network_data is not None
    assert result.network_data.rejected is True
    assert "CGNAT" in result.network_data.rejection_reason


# --- public IPv6 connection handling -----------------------------------------


def test_ssl_scan_dials_a_validated_public_ipv6_address(monkeypatch, dials):
    _fake_dns(monkeypatch, {"v6.example": ["2606:4700:4700::1111"]})

    SSLModule().run("v6.example")

    assert dials == [("2606:4700:4700::1111", 443)]


def test_http_fetch_dials_a_validated_public_ipv6_address(monkeypatch, dials):
    _fake_dns(monkeypatch, {"v6.example": ["2606:4700:4700::1111"]})

    result = http_client.fetch_url("https://v6.example/")

    assert isinstance(result, http_client.FetchError)  # refused by the dial double, after validation
    assert dials == [("2606:4700:4700::1111", 443)]


def test_port_scanner_dials_a_public_ipv6_target_on_allowed_ports_only(dials):
    from app.config import settings

    PortScannerModule().run("2606:4700:4700::1111")

    assert sorted(port for _ip, port in dials) == sorted(settings.allowed_scan_ports)
    assert {ip for ip, _port in dials} == {"2606:4700:4700::1111"}
