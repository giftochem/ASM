"""Unit tests for CertificateDiscoveryProvider — no public Internet.
Reuses test_tls_pinning.py's local self-signed TLS server pattern
(real cert, real handshake, real cryptography parsing) rather than
hand-built fakes; net_safety.resolve_and_validate is monkeypatched to
point at the local server (matching how the DNS provider's tests
isolate at the dns.resolver boundary — net_safety has its own
independent test suite already).
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
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

import app.discovery.certificate_provider as certificate_provider_module
from app.core.enums import AssetType, RelationshipType
from app.discovery.certificate_provider import CertificateDiscoveryProvider
from app.scanners import net_safety


def _generate_self_signed_cert(
    hostname: str,
    extra_sans: list[str] | None = None,
    expired: bool = False,
    include_san: bool = True,
    key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey | None = None,
) -> tuple[bytes, bytes]:
    key = key or rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    now = datetime.datetime.now(datetime.timezone.utc)
    if expired:
        not_before, not_after = now - datetime.timedelta(days=30), now - datetime.timedelta(days=1)
    else:
        not_before, not_after = now - datetime.timedelta(days=1), now + datetime.timedelta(days=365)

    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )
    if include_san:
        san_names = [hostname, *(extra_sans or [])]
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(n) for n in san_names]), critical=False
        )
    cert = builder.sign(key, hashes.SHA256())
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    return cert_pem, key_pem


class _LocalTLSServer:
    def __init__(self, hostname: str, port: int = 0, **cert_kwargs):
        cert_pem, key_pem = _generate_self_signed_cert(hostname, **cert_kwargs)

        certfile = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
        certfile.write(cert_pem)
        certfile.close()
        keyfile = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
        keyfile.write(key_pem)
        keyfile.close()
        self.cert_path = certfile.name
        self._key_path = keyfile.name

        self._ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._ssl_ctx.load_cert_chain(self.cert_path, self._key_path)

        self.hostname = hostname
        self.ip = "127.0.0.1"
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # port=0 (default) binds an ephemeral port; a caller simulating
        # certificate rotation (same hostname:port, new cert) can pass
        # the previous server's port explicitly to reuse it.
        self._listener.bind((self.ip, port))
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
                tls_conn = self._ssl_ctx.wrap_socket(conn, server_side=True)
                tls_conn.close()
            except Exception:
                try:
                    conn.close()
                except Exception:
                    pass

    def close(self):
        """Idempotent -- a test simulating certificate rotation may close
        a server explicitly mid-test (to free its port for reuse), and
        the fixture's own teardown will still try to close it again.
        """
        if self._stop:
            return
        self._stop = True
        self._listener.close()
        self._thread.join(timeout=2)
        os.unlink(self.cert_path)
        os.unlink(self._key_path)


class _PlainTCPServer:
    """Accepts connections but never speaks TLS -- for handshake-failure
    tests. Sends a few garbage bytes so the client's TLS handshake fails
    promptly instead of just idling.
    """

    def __init__(self):
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
                conn.send(b"not a tls handshake")
                conn.close()
            except Exception:
                pass

    def close(self):
        self._stop = True
        self._listener.close()
        self._thread.join(timeout=2)


@pytest.fixture
def tls_server():
    servers: list[_LocalTLSServer] = []

    def _make(hostname: str, **cert_kwargs) -> _LocalTLSServer:
        server = _LocalTLSServer(hostname, **cert_kwargs)
        servers.append(server)
        return server

    yield _make
    for server in servers:
        server.close()


@pytest.fixture
def plain_tcp_server():
    servers: list[_PlainTCPServer] = []

    def _make() -> _PlainTCPServer:
        server = _PlainTCPServer()
        servers.append(server)
        return server

    yield _make
    for server in servers:
        server.close()


def _point_provider_at(monkeypatch, server) -> None:
    """Monkeypatches net_safety at its canonical module location (a
    singleton -- affects every importer, including the provider) and the
    provider's own hardcoded port constant, so discover() connects to the
    local test server instead of real port 443.
    """

    def _fake_resolve_and_validate(host, port):
        return net_safety.SafeTarget(host=host, port=port, resolved_ips=[server.ip])

    monkeypatch.setattr(net_safety, "resolve_and_validate", _fake_resolve_and_validate)
    monkeypatch.setattr(certificate_provider_module, "_DEFAULT_PORT", server.port)


def test_provider_supports_domain_and_subdomain_only():
    provider = CertificateDiscoveryProvider()
    assert provider.supports(AssetType.domain) is True
    assert provider.supports(AssetType.subdomain) is True
    assert provider.supports(AssetType.ip_address) is False
    assert provider.supports(AssetType.url) is False


def test_successful_retrieval_extracts_core_fields(tls_server, monkeypatch):
    server = tls_server("authorized.test")
    _point_provider_at(monkeypatch, server)

    result = CertificateDiscoveryProvider().discover("authorized.test")

    assert result.error is None
    cert = result.certificate_data
    assert cert.hostname == "authorized.test"
    assert cert.port == server.port
    assert cert.subject is not None and "authorized.test" in cert.subject
    assert cert.issuer == cert.subject  # self-signed
    assert cert.is_self_signed is True
    assert cert.is_expired is False
    assert len(cert.fingerprint_sha256) == 64  # sha256 hex digest
    assert cert.certificate_version == "v3"
    assert cert.public_key_algorithm == "RSA"
    assert cert.public_key_size == 2048
    assert cert.protocol_version is not None
    assert cert.signature_algorithm is not None


def test_ec_public_key_reported_correctly(tls_server, monkeypatch):
    key = ec.generate_private_key(ec.SECP256R1())
    server = tls_server("ec-authorized.test", key=key)
    _point_provider_at(monkeypatch, server)

    result = CertificateDiscoveryProvider().discover("ec-authorized.test")

    assert result.certificate_data.public_key_algorithm.startswith("EC")


def test_expired_certificate_detected(tls_server, monkeypatch):
    server = tls_server("expired.test", expired=True)
    _point_provider_at(monkeypatch, server)

    result = CertificateDiscoveryProvider().discover("expired.test")

    assert result.error is None
    assert result.certificate_data.is_expired is True


def test_missing_san_handled_cleanly(tls_server, monkeypatch):
    server = tls_server("no-san.test", include_san=False)
    _point_provider_at(monkeypatch, server)

    result = CertificateDiscoveryProvider().discover("no-san.test")

    assert result.error is None
    assert result.certificate_data.subject_alt_names == []
    assert result.candidates == []


def test_wildcard_san_preserved_as_evidence_not_candidate(tls_server, monkeypatch):
    server = tls_server("authorized.test", extra_sans=["*.authorized.test"])
    _point_provider_at(monkeypatch, server)

    result = CertificateDiscoveryProvider().discover("authorized.test")

    assert "*.authorized.test" in result.certificate_data.subject_alt_names
    assert result.candidates == []  # wildcard never becomes a candidate asset


def test_in_scope_san_becomes_related_to_candidate_with_reduced_confidence(tls_server, monkeypatch):
    server = tls_server("authorized.test", extra_sans=["api.authorized.test"])
    _point_provider_at(monkeypatch, server)

    result = CertificateDiscoveryProvider().discover("authorized.test")

    assert len(result.candidates) == 1
    candidate = result.candidates[0]
    assert candidate.asset_type == AssetType.subdomain
    assert candidate.value == "api.authorized.test"
    assert candidate.relationship_type == RelationshipType.related_to
    assert candidate.confidence == 0.7
    assert candidate.confidence < result.certificate_data.confidence
    assert "api.authorized.test" in result.certificate_data.in_scope_sans


def test_external_san_becomes_evidence_only_not_candidate(tls_server, monkeypatch):
    server = tls_server("authorized.test", extra_sans=["vendor.example.net"])
    _point_provider_at(monkeypatch, server)

    result = CertificateDiscoveryProvider().discover("authorized.test")

    assert result.candidates == []
    assert result.certificate_data.external_sans == ["vendor.example.net"]


def test_deceptive_suffix_san_is_treated_as_external(tls_server, monkeypatch):
    """The exact trap from the instructions: 'authorized.test.evil.test'
    string-ends-with a shape resembling the seed but is not actually a
    subdomain of it.
    """
    server = tls_server("authorized.test", extra_sans=["authorized.test.evil.test"])
    _point_provider_at(monkeypatch, server)

    result = CertificateDiscoveryProvider().discover("authorized.test")

    assert result.candidates == []
    assert result.certificate_data.external_sans == ["authorized.test.evil.test"]


def test_external_sans_are_never_actively_contacted(tls_server, monkeypatch):
    """The core safety proof: a certificate naming multiple external
    hosts must result in exactly ONE socket connection -- to the seed's
    own resolved address -- never to anything the certificate merely
    mentions.
    """
    server = tls_server(
        "authorized.test", extra_sans=["evil-external.test", "vendor.example.net", "authorized.test.evil.test"]
    )
    _point_provider_at(monkeypatch, server)

    connection_attempts = []
    real_create_connection = socket.create_connection

    def _tracking_create_connection(address, *args, **kwargs):
        connection_attempts.append(address)
        return real_create_connection(address, *args, **kwargs)

    monkeypatch.setattr(certificate_provider_module.socket, "create_connection", _tracking_create_connection)

    result = CertificateDiscoveryProvider().discover("authorized.test")

    assert result.error is None
    assert len(connection_attempts) == 1
    assert connection_attempts[0] == (server.ip, server.port)
    assert len(result.certificate_data.external_sans) == 3
    assert result.candidates == []


def test_blocked_target_rejected_without_monkeypatched_net_safety(monkeypatch):
    """Deliberately does NOT patch net_safety -- proves the safety check
    is genuinely wired into the provider, not just assumed. "localhost"
    is one of net_safety's own hardcoded blocked-hostname-literals.
    """
    result = CertificateDiscoveryProvider().discover("localhost")
    assert result.error is not None
    assert "refusing to connect" in result.error


def test_connection_refused_handled_cleanly(monkeypatch):
    closed = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    closed.bind(("127.0.0.1", 0))
    port = closed.getsockname()[1]
    closed.close()

    def _fake_resolve_and_validate(host, p):
        return net_safety.SafeTarget(host=host, port=p, resolved_ips=["127.0.0.1"])

    monkeypatch.setattr(net_safety, "resolve_and_validate", _fake_resolve_and_validate)
    monkeypatch.setattr(certificate_provider_module, "_DEFAULT_PORT", port)

    result = CertificateDiscoveryProvider().discover("unreachable.test")
    assert result.error is not None
    assert result.candidates == []


def test_connection_timeout_handled_cleanly(monkeypatch):
    def _fake_resolve_and_validate(host, port):
        return net_safety.SafeTarget(host=host, port=port, resolved_ips=["127.0.0.1"])

    monkeypatch.setattr(net_safety, "resolve_and_validate", _fake_resolve_and_validate)

    def _raise_timeout(*args, **kwargs):
        raise socket.timeout("simulated timeout")

    monkeypatch.setattr(certificate_provider_module.socket, "create_connection", _raise_timeout)

    result = CertificateDiscoveryProvider().discover("slow.test")
    assert result.error is not None
    assert "timeout" in result.error.lower() or "simulated" in result.error.lower()


def test_handshake_failure_handled_cleanly(plain_tcp_server, monkeypatch):
    server = plain_tcp_server()

    def _fake_resolve_and_validate(host, port):
        return net_safety.SafeTarget(host=host, port=port, resolved_ips=[server.ip])

    monkeypatch.setattr(net_safety, "resolve_and_validate", _fake_resolve_and_validate)
    monkeypatch.setattr(certificate_provider_module, "_DEFAULT_PORT", server.port)

    result = CertificateDiscoveryProvider().discover("not-tls.test")
    assert result.error is not None
    assert result.candidates == []


def test_malformed_certificate_parsing_handled_cleanly(tls_server, monkeypatch):
    server = tls_server("authorized.test")
    _point_provider_at(monkeypatch, server)

    def _raise_parse_error(der_bytes):
        raise ValueError("simulated malformed certificate DER")

    monkeypatch.setattr(certificate_provider_module.x509, "load_der_x509_certificate", _raise_parse_error)

    result = CertificateDiscoveryProvider().discover("authorized.test")
    assert result.error is not None
    assert result.candidates == []
