"""Deterministic SSRF-primitive tests. IP literals resolve via
socket.getaddrinfo without any real DNS query (the OS/libc recognizes a
numeric address and returns it directly), so these run offline.
"""

import socket

import pytest

from app.scanners.net_safety import SafeTarget, UnsafeTarget, resolve_and_validate


@pytest.mark.parametrize(
    "host",
    [
        "localhost",
        "127.0.0.1",
        "127.0.0.53",
        "10.0.0.5",
        "172.16.0.5",
        "192.168.1.1",
        "169.254.1.1",
        "224.0.0.1",
        "0.0.0.0",
        "::1",
        "fe80::1",
        "fc00::1",
        "ff02::1",
        "::",
        "::ffff:127.0.0.1",  # IPv4-mapped loopback — the classic filter-bypass form
        "::ffff:169.254.169.254",  # IPv4-mapped cloud metadata address
        "::ffff:10.0.0.1",  # IPv4-mapped private address
    ],
)
def test_blocked_addresses_are_rejected(host):
    result = resolve_and_validate(host, 443)
    assert isinstance(result, UnsafeTarget), f"expected {host} to be blocked, got {result}"


def test_public_ip_is_allowed():
    result = resolve_and_validate("93.184.216.34", 443)
    assert isinstance(result, SafeTarget)
    assert result.resolved_ips == ["93.184.216.34"]


def test_disallowed_port_is_rejected_even_for_public_ip():
    result = resolve_and_validate("93.184.216.34", 22)
    assert isinstance(result, UnsafeTarget)
    assert "port" in result.reason


def test_allowed_ports_accept_public_ip():
    for port in (80, 443, 8080, 8443):
        result = resolve_and_validate("93.184.216.34", port)
        assert isinstance(result, SafeTarget), f"port {port} should be allowed"


def test_dns_resolution_failure_is_blocked(monkeypatch):
    def _raise(*args, **kwargs):
        raise socket.gaierror("simulated resolution failure")

    monkeypatch.setattr(socket, "getaddrinfo", _raise)
    result = resolve_and_validate("example.com", 443)
    assert isinstance(result, UnsafeTarget)
    assert "DNS resolution failed" in result.reason


def test_blocked_hostname_literal_short_circuits_without_dns(monkeypatch):
    def _fail_if_called(*args, **kwargs):
        raise AssertionError("getaddrinfo should not be called for a blocked literal")

    monkeypatch.setattr(socket, "getaddrinfo", _fail_if_called)
    result = resolve_and_validate("localhost", 443)
    assert isinstance(result, UnsafeTarget)
