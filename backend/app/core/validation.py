"""Strict validation/normalization for user-supplied scan targets.

Every asset value that reaches a scanner module passes through here first.
None of the Phase 1 scanner modules shell out to external processes (WHOIS
and DNS use pure-Python libraries, SSL inspection uses the stdlib `ssl`
socket API) so there is no shell-injection surface today — but targets are
still validated strictly as defense in depth and because a malformed value
should never reach a network call in the first place.
"""

import ipaddress
import re
from urllib.parse import urlparse

from app.core.enums import AssetType
from app.core.exceptions import InvalidTargetError

_LABEL_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")
_MAX_HOSTNAME_LENGTH = 253
_ASN_RE = re.compile(r"^(AS)?(\d{1,10})$", re.IGNORECASE)
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f]")

# IPv6 ranges aren't covered by the configurable IPv4 prefix-length cap
# (MAX_IP_RANGE_PREFIX_LENGTH is documented as IPv4-specific). /64 is the
# conventional smallest routed IPv6 allocation, used here as a sane fixed
# ceiling until this whole cap moves to a per-organization setting.
_MAX_IPV6_RANGE_PREFIX_LENGTH = 64

# RFC 6598 Shared Address Space (carrier-grade NAT). Not globally
# routable, so never an externally visible asset -- and Python's ipaddress
# module classifies it as neither private nor reserved, so it needs an
# explicit check. Some cloud platforms serve internal endpoints from it
# (Alibaba Cloud's instance metadata service is 100.100.100.200), which
# makes it an SSRF target, not just an unusual range. Also used by
# app.scanners.net_safety, so asset validation and connection-time checks
# can't drift apart.
SHARED_ADDRESS_SPACE = ipaddress.IPv4Network("100.64.0.0/10")

# IPv4-mapped IPv6 (::ffff:a.b.c.d) is just an IPv4 address in IPv6
# notation. Python 3.12+ classifies it by the embedded IPv4, so a form like
# ::ffff:100.100.100.200 matches none of the is_* properties and would slip
# past an IPv4-only rule such as the CGNAT check -- and it would duplicate
# the plain IPv4 asset anyway. Refused as an asset value; register the
# IPv4 address itself.
_IPV4_MAPPED_SPACE = ipaddress.IPv6Network("::ffff:0:0/96")


def normalize_hostname(value: str) -> str:
    return value.strip().rstrip(".").lower()


def validate_hostname(value: str) -> str:
    """Validate a domain/subdomain per RFC 1035 label rules. Returns the
    normalized (lowercased) form, or raises InvalidTargetError.
    """
    hostname = normalize_hostname(value)
    if not hostname or len(hostname) > _MAX_HOSTNAME_LENGTH:
        raise InvalidTargetError(f"'{value}' is not a valid hostname length")
    labels = hostname.split(".")
    if len(labels) < 2:
        raise InvalidTargetError(f"'{value}' must have at least a domain and a TLD label")
    for label in labels:
        if not _LABEL_RE.match(label):
            raise InvalidTargetError(f"'{value}' contains an invalid label: '{label}'")
    if labels[-1].isdigit():
        raise InvalidTargetError(f"'{value}' has a purely numeric TLD, which is not valid")
    return hostname


def validate_ip_address(value: str) -> str:
    value = value.strip()
    try:
        ip = ipaddress.ip_address(value)
    except ValueError as exc:
        raise InvalidTargetError(f"'{value}' is not a valid IP address") from exc
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        raise InvalidTargetError(
            f"'{value}' is an IPv4-mapped IPv6 address; register the IPv4 address ({ip.ipv4_mapped}) itself"
        )
    # ASM's whole premise is externally visible assets — private/link-
    # local/reserved addresses aren't externally reachable at all, and
    # (as of Phase 3a) accepting one here is what would let the port
    # scanner actively probe an internal network. Mirrors the same
    # category of checks app.scanners.net_safety already applies to
    # outbound HTTP fetches, for the same reason.
    if (
        ip.is_loopback
        or ip.is_multicast
        or ip.is_unspecified
        or ip.is_private
        or ip.is_link_local
        or ip.is_reserved
        or (ip.version == 4 and ip in SHARED_ADDRESS_SPACE)
    ):
        raise InvalidTargetError(
            f"'{value}' is a loopback/private/link-local/multicast/reserved/unspecified/"
            "shared-address-space (CGNAT) address and is not a valid external asset target"
        )
    return str(ip)


def validate_ip_range(value: str, max_ipv4_prefix_length: int) -> str:
    """Validate a CIDR range. `max_ipv4_prefix_length` is the smallest
    prefix length (i.e. largest range) accepted for IPv4 — passed in by the
    caller (currently app settings) rather than read from settings directly
    here, so this stays easy to swap for a per-organization value later.
    """
    value = value.strip()
    try:
        network = ipaddress.ip_network(value, strict=True)
    except ValueError as exc:
        raise InvalidTargetError(f"'{value}' is not a valid CIDR range") from exc
    if network.version == 6 and network.overlaps(_IPV4_MAPPED_SPACE):
        raise InvalidTargetError(
            f"'{value}' overlaps IPv4-mapped IPv6 space (::ffff:0:0/96); register IPv4 ranges in IPv4 form"
        )

    if (
        network.is_loopback
        or network.is_multicast
        or network.is_unspecified
        or network.is_private
        or network.is_link_local
        or network.is_reserved
        or (network.version == 4 and network.overlaps(SHARED_ADDRESS_SPACE))
    ):
        raise InvalidTargetError(
            f"'{value}' falls within a loopback/private/link-local/multicast/reserved/"
            "unspecified/shared-address-space (CGNAT) range and is not a valid external asset target"
        )

    cap = max_ipv4_prefix_length if network.version == 4 else _MAX_IPV6_RANGE_PREFIX_LENGTH
    if network.prefixlen < cap:
        raise InvalidTargetError(
            f"'{value}' exceeds the maximum allowed range size (/{cap} for "
            f"IPv{network.version})"
        )
    return str(network)


def validate_url(value: str) -> str:
    value = value.strip()
    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https"):
        raise InvalidTargetError(f"'{value}' must use http or https")
    if not parsed.hostname:
        raise InvalidTargetError(f"'{value}' has no host component")

    host = parsed.hostname
    try:
        validate_ip_address(host)
    except InvalidTargetError:
        validate_hostname(host)

    normalized_netloc = host.lower()
    if parsed.port:
        normalized_netloc += f":{parsed.port}"
    return parsed._replace(netloc=normalized_netloc).geturl()


def is_hostname_in_scope(candidate: str, seed: str) -> bool:
    """Proper DNS label-boundary check for discovery scope validation
    (Step 9.2) -- deliberately NOT a string suffix/prefix match, which
    "example.com.evil.com" would slip through (it string-endswith
    "example.com" but is a completely different, attacker-controlled
    domain the seed's owner has no authority over). A hostname is in
    scope only if its labels, split on ".", end with the seed's labels
    aligned on a full label boundary.
    """
    seed_labels = seed.strip().rstrip(".").lower().split(".")
    candidate_labels = candidate.strip().rstrip(".").lower().split(".")
    if len(candidate_labels) < len(seed_labels):
        return False
    return candidate_labels[len(candidate_labels) - len(seed_labels):] == seed_labels


def validate_asn(value: str) -> str:
    """Accepts "AS15169" or plain "15169"; normalizes to "AS{number}"."""
    match = _ASN_RE.match(value.strip())
    if not match:
        raise InvalidTargetError(f"'{value}' is not a valid ASN (expected e.g. 'AS15169' or '15169')")
    return f"AS{match.group(2)}"


def validate_generic_identifier(value: str) -> str:
    """Intentionally minimal: strip, reject empty, reject embedded control
    characters. Used for asset types (api, cloud_resource, repository)
    whose real-world identifier formats vary too much by provider
    (ARNs, GCP resource names, git URLs, ...) to validate strictly yet —
    the existing 255-char cap is enforced by the Pydantic schema layer,
    not here. Real per-provider format rules are future work, not a
    silent gap: this only rules out obviously-malformed input.
    """
    stripped = value.strip()
    if not stripped:
        raise InvalidTargetError("value must not be empty")
    if _CONTROL_CHAR_RE.search(stripped):
        raise InvalidTargetError(f"'{value}' contains control characters, which is not a valid identifier")
    return stripped


def normalize_asset_value(
    asset_type: AssetType, value: str, max_ipv4_range_prefix_length: int
) -> str:
    """Validate `value` against the rules for `asset_type` and return its
    normalized form. Raises InvalidTargetError on any violation.

    Some AssetType values (service, tls_certificate, web3_*, rpc_endpoint)
    are deliberately reserved-but-not-creatable — see the enum's
    docstring in app.core.enums for why — and fall through to the
    unsupported-type error below unchanged.
    """
    if asset_type in (AssetType.domain, AssetType.subdomain):
        return validate_hostname(value)
    if asset_type is AssetType.ip_address:
        return validate_ip_address(value)
    if asset_type is AssetType.ip_range:
        return validate_ip_range(value, max_ipv4_range_prefix_length)
    if asset_type is AssetType.url:
        return validate_url(value)
    if asset_type is AssetType.asn:
        return validate_asn(value)
    if asset_type is AssetType.http_endpoint:
        return validate_url(value)
    if asset_type in (AssetType.api, AssetType.cloud_resource, AssetType.repository):
        return validate_generic_identifier(value)
    raise InvalidTargetError(f"unsupported asset type: {asset_type}")
