"""app.scanners.ssl_module must route every outbound connection through
net_safety: no private/loopback/link-local/reserved/multicast target is
ever dialed, only allowed ports are used, and both connections it makes
are pinned to an address net_safety already validated (the hostname is
never resolved a second time, so DNS rebinding can't redirect them).

Hermetic: DNS answers are faked via socket.getaddrinfo, and the only real
TLS handshake is with a local self-signed server on 127.0.0.1 -- no
external host is ever contacted.
"""

import datetime
import os
import socket
import ssl
import tempfile
import threading

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app.scanners import net_safety, ssl_module
from app.scanners.ssl_module import SSLModule

_PUBLIC_IP = "93.184.216.34"
_SECOND_PUBLIC_IP = "93.184.216.35"


def _fake_dns(monkeypatch, answers: dict[str, list[str]], lookups: list | None = None) -> None:
    passthrough = socket.getaddrinfo

    def fake_getaddrinfo(host, port, *args, **kwargs):
        if host not in answers:
            return passthrough(host, port, *args, **kwargs)
        if lookups is not None:
            lookups.append(host)
        results = []
        for ip in answers[host]:
            if ":" in ip:
                results.append((socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, port, 0, 0)))
            else:
                results.append((socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, port)))
        return results

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)


def _no_dns_expected(monkeypatch) -> None:
    def fail(*args, **kwargs):
        raise AssertionError("no DNS lookup was expected for this target")

    monkeypatch.setattr(socket, "getaddrinfo", fail)


@pytest.fixture
def dial_log(monkeypatch):
    """Records every TCP dial and refuses it -- nothing reaches a network."""
    dialed: list[tuple] = []

    def refusing_create_connection(address, *args, **kwargs):
        dialed.append(address)
        raise ConnectionRefusedError("test double: not actually connecting")

    monkeypatch.setattr(socket, "create_connection", refusing_create_connection)
    return dialed


@pytest.mark.parametrize(
    "blocked_ip",
    [
        "127.0.0.1",
        "10.0.0.5",
        "172.16.3.4",
        "192.168.1.10",
        "169.254.169.254",  # cloud metadata endpoint
        "0.0.0.0",
        "224.0.0.1",
        "::1",
        "fe80::1",
        "::ffff:127.0.0.1",  # IPv4-mapped loopback
    ],
)
def test_hostname_resolving_to_a_blocked_address_is_never_contacted(monkeypatch, dial_log, blocked_ip):
    _fake_dns(monkeypatch, {"internal.example": [blocked_ip]})

    result = SSLModule().run("internal.example")

    assert result.error is not None
    assert result.error.startswith("Refusing to connect to internal.example:443")
    assert result.findings == []
    assert dial_log == []


def test_one_blocked_address_among_several_rejects_the_whole_target(monkeypatch, dial_log):
    _fake_dns(monkeypatch, {"mixed.example": [_PUBLIC_IP, "10.0.0.7"]})

    result = SSLModule().run("mixed.example")

    assert result.error.startswith("Refusing to connect to mixed.example:443")
    assert dial_log == []


def test_blocked_hostname_literal_is_rejected_without_any_dns_lookup(monkeypatch, dial_log):
    _no_dns_expected(monkeypatch)

    result = SSLModule().run("localhost")

    assert result.error.startswith("Refusing to connect to localhost:443")
    assert dial_log == []


def test_private_ip_literal_target_is_rejected(dial_log):
    result = SSLModule().run("10.1.2.3")

    assert result.error.startswith("Refusing to connect to 10.1.2.3:443")
    assert dial_log == []


def test_url_with_disallowed_port_is_rejected_before_any_resolution(monkeypatch, dial_log):
    _no_dns_expected(monkeypatch)

    result = SSLModule().run("https://example.com:6379/")

    assert result.error.startswith("Refusing to connect to example.com:6379")
    assert "not in the allowed scan port set" in result.error
    assert dial_log == []


def test_url_with_allowed_non_default_port_dials_the_validated_ip(monkeypatch, dial_log):
    _fake_dns(monkeypatch, {"tls-alt.example": [_PUBLIC_IP]})

    result = SSLModule().run("https://tls-alt.example:8443/")

    assert dial_log == [(_PUBLIC_IP, 8443)]
    assert result.error.startswith("Could not retrieve certificate from tls-alt.example:8443")


def test_public_ip_literal_target_is_dialed_directly(dial_log):
    SSLModule().run(_PUBLIC_IP)

    assert dial_log == [(_PUBLIC_IP, 443)]


def test_connection_is_pinned_to_the_validated_ip_not_a_rebound_answer(monkeypatch, dial_log):
    lookups: list[str] = []
    passthrough = socket.getaddrinfo

    def rebinding_getaddrinfo(host, port, *args, **kwargs):
        if host != "rebind.example":
            return passthrough(host, port, *args, **kwargs)
        lookups.append(host)
        # First answer (what net_safety validates) is public; any later
        # lookup would get a private address -- a rebinding resolver.
        ip = _PUBLIC_IP if len(lookups) == 1 else "10.0.0.99"
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, port))]

    monkeypatch.setattr(socket, "getaddrinfo", rebinding_getaddrinfo)

    SSLModule().run("rebind.example")

    assert lookups == ["rebind.example"], "the hostname must be resolved exactly once, by net_safety"
    assert dial_log == [(_PUBLIC_IP, 443)]


def test_unreachable_first_address_falls_back_to_the_next_validated_one_only(monkeypatch, dial_log):
    _fake_dns(monkeypatch, {"multi.example": [_PUBLIC_IP, _SECOND_PUBLIC_IP]})

    SSLModule().run("multi.example")

    assert dial_log == [(_PUBLIC_IP, 443), (_SECOND_PUBLIC_IP, 443)]


def test_deprecated_tls_probe_dials_the_pinned_ip_not_the_hostname(dial_log):
    assert ssl_module._supports_deprecated_tls("pinned.example", 443, _PUBLIC_IP) is False
    assert dial_log == [(_PUBLIC_IP, 443)]


# --- legitimate TLS inspection still works --------------------------------


def _generate_self_signed_cert(hostname: str) -> tuple[bytes, bytes]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=90))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    return cert.public_bytes(serialization.Encoding.PEM), key_pem


class _LocalTLSServer:
    """A TLS listener on 127.0.0.1 presenting a self-signed certificate for
    one hostname, recording the SNI name each client sent."""

    def __init__(self, hostname: str):
        cert_pem, key_pem = _generate_self_signed_cert(hostname)
        self._paths = []
        for suffix, content in ((".crt.pem", cert_pem), (".key.pem", key_pem)):
            handle = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
            handle.write(content)
            handle.close()
            self._paths.append(handle.name)

        self.sni_names: list[str | None] = []
        self._ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._ssl_ctx.load_cert_chain(self._paths[0], self._paths[1])
        self._ssl_ctx.sni_callback = lambda _sock, server_name, _ctx: self.sni_names.append(server_name)

        self.ip = "127.0.0.1"
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind((self.ip, 0))
        self._listener.listen(5)
        self.port = self._listener.getsockname()[1]
        self._stop = False
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        while not self._stop:
            self._listener.settimeout(0.5)
            try:
                conn, _ = self._listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                with self._ssl_ctx.wrap_socket(conn, server_side=True) as tls_conn:
                    tls_conn.recv(1)
            except Exception:
                # Expected: the client closes right after reading the
                # certificate, and the deprecated-TLS probe's handshake fails.
                conn.close()

    def close(self):
        self._stop = True
        self._listener.close()
        self._thread.join(timeout=2)
        for path in self._paths:
            os.unlink(path)


@pytest.fixture
def tls_server():
    servers: list[_LocalTLSServer] = []

    def _make(hostname: str) -> _LocalTLSServer:
        server = _LocalTLSServer(hostname)
        servers.append(server)
        return server

    yield _make
    for server in servers:
        server.close()


def test_legitimate_tls_inspection_still_works_through_the_pinned_path(monkeypatch, tls_server):
    server = tls_server("public-tls.example")
    validations: list[tuple] = []

    def validated_to_local_server(host, port):
        # Stands in for "public-tls.example resolved to a validated public
        # address": the pinned dial is pointed at the local test server so
        # the real handshake and certificate parsing run without contacting
        # any external host.
        validations.append((host, port))
        return net_safety.SafeTarget(host=host, port=port, resolved_ips=[server.ip])

    monkeypatch.setattr(net_safety, "resolve_and_validate", validated_to_local_server)
    dialed: list[tuple] = []
    real_create_connection = socket.create_connection

    def recording_create_connection(address, *args, **kwargs):
        dialed.append(address)
        return real_create_connection(address, *args, **kwargs)

    monkeypatch.setattr(socket, "create_connection", recording_create_connection)

    result = SSLModule().run(f"https://public-tls.example:{server.port}/")

    assert result.error is None
    assert validations == [("public-tls.example", server.port)]
    assert dialed and all(address == (server.ip, server.port) for address in dialed)
    assert set(server.sni_names) == {"public-tls.example"}, "SNI must still carry the real hostname"
    assert result.raw_data["hostname"] == "public-tls.example"
    assert "CN=public-tls.example" in result.raw_data["subject"]
    assert result.raw_data["subject_alt_names"] == ["public-tls.example"]
    assert result.raw_data["is_self_signed"] is True
    titles = {finding.title for finding in result.findings}
    assert "TLS certificate retrieved" in titles
    assert "Self-signed TLS certificate" in titles
