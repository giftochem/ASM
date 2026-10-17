import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

from cryptography import x509
from cryptography.x509.oid import ExtensionOID

from app.core.enums import AssetType, FindingSeverity
from app.scanners import net_safety
from app.scanners.base import ScanFinding, ScanModuleResult, ScannerModule

_CONNECT_TIMEOUT_SECONDS = 5.0
_EXPIRY_WARNING_DAYS = 30
_DEFAULT_PORT = 443


def _target_host_port(target: str) -> tuple[str, int]:
    if "://" in target:
        parsed = urlparse(target)
        return parsed.hostname, parsed.port or _DEFAULT_PORT
    return target, _DEFAULT_PORT


def _connect_pinned(validated_ips: list[str], port: int) -> tuple[socket.socket, str]:
    """Dials only addresses net_safety.resolve_and_validate already
    approved -- the hostname is never resolved again here, so a DNS
    answer that changes after validation (rebinding) can't redirect the
    connection. Tries each in resolution order, as socket.create_connection
    does for a hostname, so a multi-address host whose first address is
    unreachable is still inspected. Returns the socket and the IP it
    reached."""
    last_error: OSError | None = None
    for ip in validated_ips:
        try:
            return socket.create_connection((ip, port), timeout=_CONNECT_TIMEOUT_SECONDS), ip
        except OSError as exc:
            last_error = exc
    raise last_error if last_error is not None else OSError("no validated address to connect to")


def _fetch_certificate(
    host: str, port: int, validated_ips: list[str]
) -> tuple[x509.Certificate, str | None, str | None, str]:
    """Connects to a validated IP while still sending `host` as SNI --
    the same pinning approach as app.discovery.certificate_provider and
    pinned_transport.py: only which IP the TCP layer dials is pinned,
    certificate inspection itself is unchanged."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    sock, connected_ip = _connect_pinned(validated_ips, port)
    with sock:
        with context.wrap_socket(sock, server_hostname=host) as tls_sock:
            der_cert = tls_sock.getpeercert(binary_form=True)
            protocol_version = tls_sock.version()
            cipher = tls_sock.cipher()
            cipher_suite = cipher[0] if cipher else None
    certificate = x509.load_der_x509_certificate(der_cert)
    return certificate, protocol_version, cipher_suite, connected_ip


def _supports_deprecated_tls(host: str, port: int, pinned_ip: str) -> bool:
    """Best-effort check for TLS 1.0/1.1 support. Many OpenSSL builds
    disable these protocols entirely, in which case the handshake simply
    fails and we correctly report "not supported" rather than erroring.

    Dials `pinned_ip` -- the address the certificate fetch already
    reached -- never re-resolving `host`, so this second connection can't
    be steered elsewhere by a changed DNS answer.
    """
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = ssl.TLSVersion.TLSv1
        context.maximum_version = ssl.TLSVersion.TLSv1_1
        with socket.create_connection((pinned_ip, port), timeout=_CONNECT_TIMEOUT_SECONDS) as sock:
            with context.wrap_socket(sock, server_hostname=host):
                return True
    except Exception:
        return False


class SSLModule(ScannerModule):
    name = "ssl"
    applicable_asset_types = {
        AssetType.domain,
        AssetType.subdomain,
        AssetType.ip_address,
        AssetType.url,
    }

    def run(self, target: str) -> ScanModuleResult:
        host, port = _target_host_port(target)
        if not host:
            return ScanModuleResult(module=self.name, error=f"Could not determine host from '{target}'")

        # Every connection this module makes is gated here first: allowed
        # port, blocked hostname literals, and EVERY resolved address
        # checked against net_safety's private/loopback/link-local/
        # reserved/multicast rules. Nothing is dialed for an unsafe target.
        validation = net_safety.resolve_and_validate(host, port)
        if isinstance(validation, net_safety.UnsafeTarget):
            return ScanModuleResult(
                module=self.name, error=f"Refusing to connect to {host}:{port}: {validation.reason}"
            )

        try:
            cert, protocol_version, cipher_suite, connected_ip = _fetch_certificate(
                host, port, validation.resolved_ips
            )
        except Exception as exc:
            return ScanModuleResult(
                module=self.name, error=f"Could not retrieve certificate from {host}:{port}: {exc}"
            )

        issuer = cert.issuer.rfc4514_string()
        subject = cert.subject.rfc4514_string()
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
        is_self_signed = issuer == subject

        try:
            san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            san_names = san_ext.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            san_names = []

        now = datetime.now(timezone.utc)
        days_left = (not_after - now).days
        is_expired = days_left < 0

        findings = [
            ScanFinding(
                title="TLS certificate retrieved",
                description=f"Subject: {subject} | Issuer: {issuer} | Protocol: {protocol_version}",
                severity=FindingSeverity.info,
                confidence=1.0,
                evidence={
                    "subject": subject,
                    "issuer": issuer,
                    "not_before": not_before.isoformat(),
                    "not_after": not_after.isoformat(),
                    "protocol_version": protocol_version,
                    "cipher_suite": cipher_suite,
                    "san": san_names,
                },
            )
        ]

        if is_expired:
            findings.append(
                ScanFinding(
                    title="TLS certificate has expired",
                    description=f"Certificate for {host} expired {abs(days_left)} day(s) ago.",
                    severity=FindingSeverity.critical,
                    confidence=1.0,
                )
            )
        elif days_left <= _EXPIRY_WARNING_DAYS:
            findings.append(
                ScanFinding(
                    title="TLS certificate expiring soon",
                    description=f"Certificate for {host} expires in {days_left} day(s).",
                    severity=FindingSeverity.medium,
                    confidence=1.0,
                )
            )

        if is_self_signed:
            findings.append(
                ScanFinding(
                    title="Self-signed TLS certificate",
                    description=f"The certificate presented by {host} is self-signed and not "
                    "issued by a trusted CA.",
                    severity=FindingSeverity.medium,
                    confidence=1.0,
                )
            )

        if _supports_deprecated_tls(host, port, connected_ip):
            findings.append(
                ScanFinding(
                    title="Deprecated TLS protocol accepted",
                    description=f"{host}:{port} accepted a handshake restricted to TLS 1.0/1.1, "
                    "both deprecated and considered insecure.",
                    severity=FindingSeverity.high,
                    confidence=0.9,
                )
            )

        return ScanModuleResult(
            module=self.name,
            findings=findings,
            raw_data={
                "hostname": host,
                "port": port,
                "issuer": issuer,
                "subject": subject,
                "valid_from": not_before.isoformat(),
                "valid_until": not_after.isoformat(),
                "serial_number": format(cert.serial_number, "x"),
                "signature_algorithm": cert.signature_algorithm_oid._name,
                "protocol_version": protocol_version,
                "cipher_suite": cipher_suite,
                "subject_alt_names": san_names,
                "is_expired": is_expired,
                "is_self_signed": is_self_signed,
            },
        )
