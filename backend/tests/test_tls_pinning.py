"""Proves the pinned transport (app.scanners.pinned_transport) does not
weaken TLS certificate/hostname verification. Uses a local self-signed
TLS server rather than live external infrastructure: an earlier attempt
to prove this with a real "wrong" public IP (Cloudflare's 1.1.1.1)
unexpectedly succeeded, because that shared anycast IP also happened to
terminate TLS for an unrelated customer's domain literally named
"example.com" via a custom-hostname/SSL-for-SaaS feature -- a real
demonstration of why relying on live third-party infrastructure for a
security-verification test is unreliable, not just slow.
"""

import datetime
import os
import socket
import ssl
import tempfile
import threading

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app.scanners.pinned_transport import build_pinned_transport


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
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return cert_pem, key_pem


class _LocalTLSServer:
    """A minimal single-response-at-a-time HTTPS server bound to
    127.0.0.1 on an ephemeral port, presenting a self-signed cert for
    exactly one hostname.
    """

    def __init__(self, hostname: str):
        cert_pem, key_pem = _generate_self_signed_cert(hostname)

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
                tls_conn = self._ssl_ctx.wrap_socket(conn, server_side=True)
                tls_conn.recv(4096)
                tls_conn.send(
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: text/plain\r\n"
                    b"Content-Length: 2\r\n"
                    b"Connection: close\r\n\r\nOK"
                )
                tls_conn.close()
            except Exception:
                # Expected whenever the client aborts the handshake (the
                # mismatched-hostname test) -- the server side just sees a
                # failed/aborted TLS negotiation.
                try:
                    conn.close()
                except Exception:
                    pass

    def close(self):
        self._stop = True
        self._listener.close()
        self._thread.join(timeout=2)
        os.unlink(self.cert_path)
        os.unlink(self._key_path)


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


def test_pinned_connection_succeeds_with_matching_hostname_and_trusted_ca(tls_server):
    """Positive case: pin to the server's real IP, request the hostname
    the cert actually covers, trust that cert's own PEM as the CA (since
    it's self-signed) -- must succeed and return real content.
    """
    server = tls_server("correct-host.test")
    transport = build_pinned_transport(server.ip, verify=ssl.create_default_context(cafile=server.cert_path))
    with httpx.Client(transport=transport, timeout=5.0) as client:
        resp = client.get(f"https://{server.hostname}:{server.port}/")
        assert resp.status_code == 200
        assert resp.text == "OK"


def test_pinned_connection_fails_with_mismatched_hostname(tls_server):
    """The core proof: pinning the TCP connection to a real, reachable TLS
    server does NOT bypass hostname verification. The server's cert is
    valid for "correct-host.test"; the request claims a different
    hostname. The handshake must fail even though the underlying socket
    connects successfully and even though the CA is trusted.
    """
    server = tls_server("correct-host.test")
    transport = build_pinned_transport(server.ip, verify=ssl.create_default_context(cafile=server.cert_path))
    with httpx.Client(transport=transport, timeout=5.0) as client:
        with pytest.raises(httpx.ConnectError) as exc_info:
            client.get(f"https://attacker-claimed-host.test:{server.port}/")
        message = str(exc_info.value).lower()
        assert "certificate" in message or "hostname" in message


def test_pinned_connection_rejects_self_signed_cert_without_explicit_trust(tls_server):
    """verify=True (the production default -- no custom CA supplied) must
    reject a self-signed certificate outright, matching hostname or not.
    Proves the pinned path never silently trusts an untrusted cert.
    """
    server = tls_server("correct-host.test")
    transport = build_pinned_transport(server.ip, verify=True)
    with httpx.Client(transport=transport, timeout=5.0) as client:
        with pytest.raises(httpx.ConnectError):
            client.get(f"https://{server.hostname}:{server.port}/")


def test_pinning_does_not_disable_verification_globally():
    """Guards against a regression where someone "fixes" a pinning bug by
    reaching for verify=False. build_pinned_transport's default must stay
    strict.
    """
    import inspect

    from app.scanners.pinned_transport import build_pinned_transport as fn

    assert inspect.signature(fn).parameters["verify"].default is True
