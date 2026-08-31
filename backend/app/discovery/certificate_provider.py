"""Passive TLS certificate retrieval from an authorized domain/subdomain
seed. Exactly one connection per run -- to the seed's own hostname, port
443 -- via net_safety.resolve_and_validate (the same SSRF-safe primitive
app.scanners.http_client already uses), pinning the socket to the
validated IP while still sending the real hostname as SNI. Certificate
SANs are classified (in-scope vs. external) but NEVER connected to.

Parsing uses the `cryptography` library, already a dependency via
app.scanners.ssl_module -- not reimplemented ASN.1/TLS handling. This
provider is not a replacement for ssl_module (which stays exactly as it
is -- active-scan findings, not discovery); it's a parallel,
harder-scoped path for the discovery pipeline specifically, that closes
a gap ssl_module still has (a bare socket, no pre-resolution IP
validation) without touching that existing, disclosed-debt code.

SAFETY: a certificate's SAN list is EVIDENCE, not authorization. An
in-scope SAN becomes a candidate Asset (status=first_seen -- "observed,
not confirmed live") via the normal discovery pipeline, which never sets
authorization_confirmed; an external SAN becomes evidence only. Neither
is ever connected to by this provider -- it makes exactly one TLS
connection, to the seed itself, full stop. "Give me an authorized
asset, I'll inspect its certificate and record what it tells me,
without expanding my authorization" -- not "give me a domain, I'll
scan every SAN I find."
"""

import socket
import ssl
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
from cryptography.x509.oid import ExtensionOID

from app.core.enums import AssetType, RelationshipType
from app.core.validation import is_hostname_in_scope, normalize_hostname
from app.discovery.base import (
    CertificateObservation,
    DiscoveryCandidate,
    DiscoveryProvider,
    DiscoveryProviderResult,
)
from app.scanners import net_safety

_CONNECT_TIMEOUT_SECONDS = 5.0  # matches app.scanners.ssl_module's existing constant
_DEFAULT_PORT = 443  # hardcoded -- no user/API-controlled port anywhere in this provider
_SAN_CANDIDATE_CONFIDENCE = 0.7  # claimed by a certificate, not confirmed by resolution -- lower than DNS's 1.0
_CERTIFICATE_CONFIDENCE = 1.0  # the certificate itself was directly retrieved, not inferred


def _public_key_info(certificate: x509.Certificate) -> tuple[str | None, int | None]:
    public_key = certificate.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        return "RSA", public_key.key_size
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return f"EC ({public_key.curve.name})", public_key.key_size
    if isinstance(public_key, dsa.DSAPublicKey):
        return "DSA", public_key.key_size
    return type(public_key).__name__, None


def _fetch_certificate(host: str, port: int) -> tuple[x509.Certificate, str | None, str | None]:
    """Raises on any failure -- the caller wraps this broadly and never
    lets an exception escape discover() itself, matching every other
    provider's contract. Pins the TCP connection to a net_safety-
    validated IP (unlike app.scanners.ssl_module's existing bare socket,
    a disclosed gap this deliberately doesn't inherit) while still
    sending `host` as SNI -- only which IP the TCP layer dials is
    pinned, mirroring pinned_transport.py's identical approach for HTTP;
    certificate/hostname verification semantics are unaffected.
    """
    validation = net_safety.resolve_and_validate(host, port)
    if isinstance(validation, net_safety.UnsafeTarget):
        raise ValueError(f"refusing to connect: {validation.reason}")

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((validation.resolved_ips[0], port), timeout=_CONNECT_TIMEOUT_SECONDS) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls_sock:
            der_cert = tls_sock.getpeercert(binary_form=True)
            protocol_version = tls_sock.version()
            cipher = tls_sock.cipher()
    certificate = x509.load_der_x509_certificate(der_cert)
    return certificate, protocol_version, cipher[0] if cipher else None


class CertificateDiscoveryProvider(DiscoveryProvider):
    name = "certificate"
    applicable_seed_types = {AssetType.domain, AssetType.subdomain}

    def discover(self, seed_value: str) -> DiscoveryProviderResult:
        try:
            certificate, protocol_version, cipher_suite = _fetch_certificate(seed_value, _DEFAULT_PORT)
        except Exception as exc:
            return DiscoveryProviderResult(
                provider=self.name,
                error=f"could not retrieve certificate from {seed_value}:{_DEFAULT_PORT}: {exc}",
            )

        issuer = certificate.issuer.rfc4514_string()
        subject = certificate.subject.rfc4514_string()
        not_before = certificate.not_valid_before_utc
        not_after = certificate.not_valid_after_utc
        is_self_signed = issuer == subject
        is_expired = datetime.now(timezone.utc) > not_after

        try:
            san_ext = certificate.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            san_names = san_ext.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            san_names = []

        public_key_algorithm, public_key_size = _public_key_info(certificate)

        # SAN classification -- evidence only. The one and only TLS
        # connection this method makes already happened above; nothing
        # past this point opens a socket.
        candidates: list[DiscoveryCandidate] = []
        in_scope_sans: list[str] = []
        external_sans: list[str] = []
        for raw_san in san_names:
            san = normalize_hostname(raw_san)
            if not san or san.startswith("*."):
                # A wildcard isn't a real, connectable hostname -- still
                # preserved in subject_alt_names below, just never a
                # candidate asset.
                continue
            if san == seed_value:
                continue  # the seed's own name, already tracked as the seed asset
            if is_hostname_in_scope(san, seed_value):
                in_scope_sans.append(san)
                candidates.append(
                    DiscoveryCandidate(
                        asset_type=AssetType.subdomain,
                        value=san,
                        relationship_type=RelationshipType.related_to,
                        confidence=_SAN_CANDIDATE_CONFIDENCE,
                        evidence={"source": "certificate_san", "observed_from": seed_value},
                    )
                )
            else:
                external_sans.append(san)

        certificate_data = CertificateObservation(
            hostname=seed_value,
            port=_DEFAULT_PORT,
            fingerprint_sha256=certificate.fingerprint(hashes.SHA256()).hex(),
            issuer=issuer,
            subject=subject,
            valid_from=not_before,
            valid_until=not_after,
            serial_number=format(certificate.serial_number, "x"),
            signature_algorithm=certificate.signature_algorithm_oid._name,
            protocol_version=protocol_version,
            cipher_suite=cipher_suite,
            subject_alt_names=list(san_names),
            is_expired=is_expired,
            is_self_signed=is_self_signed,
            certificate_version=certificate.version.name,
            public_key_algorithm=public_key_algorithm,
            public_key_size=public_key_size,
            in_scope_sans=in_scope_sans,
            external_sans=external_sans,
            confidence=_CERTIFICATE_CONFIDENCE,
        )

        return DiscoveryProviderResult(provider=self.name, candidates=candidates, certificate_data=certificate_data)
