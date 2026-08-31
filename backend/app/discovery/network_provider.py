"""Passive ASN/network intelligence for an authorized ip_address seed
(Step 9.6). Answers: what network/ASN announces this address, what
prefix, what does reverse DNS say, does it look like a well-known cloud
provider -- all as evidence for the attack-surface graph, never as an
active-scan or ownership claim.

Data source: Team Cymru's public IP-to-ASN DNS lookup service
(https://team-cymru.com/community-services/ip-asn-mapping/) --
DNS TXT queries against a fixed, trusted third party
(*.origin.asn.cymru.com / *.origin6.asn.cymru.com / *.asn.cymru.com),
using dnspython (already a project dependency -- see dns_provider.py).
No new dependency, no API key, no credential to manage. Deliberately
NOT routed through net_safety/pinned_transport: exactly like
subdomain_provider's crt.sh usage, the connection destination is always
this one fixed, trusted DNS service -- the seed IP is embedded in the
DNS query NAME, never used as a connection target. See
subdomain_provider.py's module docstring for the identical reasoning.
Two queries are made per candidate (origin, then AS-name) plus a third,
independent PTR query -- Team Cymru's own service is split into two
lookups by design (the origin query alone doesn't carry the AS's
registered name), so this isn't an unbounded per-candidate request loop.

SAFETY: even though the seed is already a validated ip_address Asset
by the time discover() runs (private/loopback/reserved values are
rejected at asset-creation time), this provider independently re-checks
via app.core.validation.validate_ip_address before making any lookup --
defense in depth, not a second implementation of the check.

SCOPE: a reverse-DNS (PTR) hostname is recorded as evidence ONLY, never
promoted to a candidate Asset. app.core.validation.is_hostname_in_scope
does a DNS-label-boundary comparison against a *hostname* seed -- it has
no meaning for a bare-IP seed (there is no hostname authority to compare
labels against), so there is no existing mechanism to honestly decide
"is this PTR hostname in this organization's authorized scope." Rather
than build a new, unproven scope heuristic, this provider treats every
PTR result the same conservative way: evidence only. See the Step 9.6
completion report for the full reasoning -- this is a disclosed
architectural gap, not an oversight.
"""

import ipaddress
import re

import dns.exception
import dns.resolver
import dns.reversename

from app.core.enums import AssetType, RelationshipType
from app.core.exceptions import InvalidTargetError
from app.core.validation import validate_ip_address
from app.discovery.base import (
    DiscoveryCandidate,
    DiscoveryProvider,
    DiscoveryProviderResult,
    NetworkObservation,
)

_LOOKUP_TIMEOUT_SECONDS = 5.0
# A dedicated, purpose-built registry/routing-table mirror -- more
# authoritative than a client-controlled header (Step 9.5's technology
# evidence, 0.7-0.8) but not a live, first-party resolution (DNS's own
# 1.0): Team Cymru's data is a periodically-updated mirror of BGP
# announcements, not real-time truth.
_ASN_CANDIDATE_CONFIDENCE = 0.9
_CLOUD_PROVIDER_CONFIDENCE = 0.8  # matches Step 9.5's Server-header confidence: a registered AS name is a strong, non-spoofable-by-the-client signal
# One overall confidence per NetworkObservation, not a separate value
# per field -- same granularity as CertificateObservation/HttpObservation.
# Used when only the PTR resolved (no ASN found): a directly-resolved
# DNS fact, but with no network/ASN attribution to anchor a higher
# overall confidence on.
_PARTIAL_RESULT_CONFIDENCE = 0.8

# Deliberately narrow, matching Step 9.5's "no giant signature database"
# precedent -- conservative, well-known-provider matches only, each
# labeled with exactly what evidence produced it.
_CLOUD_PROVIDER_SIGNATURES = (
    (re.compile(r"AMAZON|AWS", re.I), "Amazon Web Services"),
    (re.compile(r"GOOGLE", re.I), "Google Cloud / Google"),
    (re.compile(r"MICROSOFT|AZURE", re.I), "Microsoft Azure"),
    (re.compile(r"CLOUDFLARE", re.I), "Cloudflare"),
    (re.compile(r"DIGITALOCEAN", re.I), "DigitalOcean"),
    (re.compile(r"AKAMAI", re.I), "Akamai"),
    (re.compile(r"FASTLY", re.I), "Fastly"),
    (re.compile(r"\bOVH\b", re.I), "OVH"),
    (re.compile(r"HETZNER", re.I), "Hetzner"),
    (re.compile(r"LINODE", re.I), "Linode"),
)


def _cymru_origin_query_name(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    if ip.version == 4:
        octets = str(ip).split(".")
        return ".".join(reversed(octets)) + ".origin.asn.cymru.com"
    nibbles = ip.exploded.replace(":", "")
    return ".".join(reversed(nibbles)) + ".origin6.asn.cymru.com"


def _parse_pipe_fields(txt_value: str) -> list[str]:
    return [field.strip() for field in txt_value.strip().strip('"').split("|")]


def _infer_cloud_provider(asn_organization: str | None) -> dict | None:
    if not asn_organization:
        return None
    for pattern, provider_name in _CLOUD_PROVIDER_SIGNATURES:
        if pattern.search(asn_organization):
            return {
                "provider": provider_name,
                "confidence": _CLOUD_PROVIDER_CONFIDENCE,
                "evidence": f"AS organization name matched '{pattern.pattern}'",
            }
    return None


class NetworkDiscoveryProvider(DiscoveryProvider):
    name = "network"
    applicable_seed_types = {AssetType.ip_address}

    def discover(self, seed_value: str) -> DiscoveryProviderResult:
        try:
            ip = ipaddress.ip_address(seed_value)
        except ValueError as exc:
            return DiscoveryProviderResult(
                provider=self.name, error=f"'{seed_value}' is not a valid IP address: {exc}"
            )

        try:
            validate_ip_address(seed_value)
        except InvalidTargetError as exc:
            return DiscoveryProviderResult(
                provider=self.name,
                network_data=NetworkObservation(
                    ip=seed_value,
                    ip_version=ip.version,
                    rejected=True,
                    rejection_reason=str(exc),
                ),
            )

        resolver = dns.resolver.Resolver()
        resolver.timeout = _LOOKUP_TIMEOUT_SECONDS
        resolver.lifetime = _LOOKUP_TIMEOUT_SECONDS

        asn = None
        announced_prefix = None
        network_country = None
        registry = None
        asn_organization = None

        origin_fields = self._query_origin(resolver, ip)
        if origin_fields is not None:
            asn = origin_fields.get("asn")
            announced_prefix = origin_fields.get("prefix")
            network_country = origin_fields.get("country")
            registry = origin_fields.get("registry")
            if asn:
                asname_fields = self._query_asn_name(resolver, asn)
                if asname_fields is not None:
                    asn_organization = asname_fields.get("as_name")

        ptr_hostname = self._query_ptr(resolver, seed_value)

        if origin_fields is None and ptr_hostname is None:
            return DiscoveryProviderResult(
                provider=self.name,
                network_data=NetworkObservation(
                    ip=seed_value,
                    ip_version=ip.version,
                    succeeded=False,
                    failure_reason="no ASN/prefix or PTR data returned for this address",
                ),
            )

        cloud_provider_evidence = _infer_cloud_provider(asn_organization)

        candidates: list[DiscoveryCandidate] = []
        formatted_asn = f"AS{asn}" if asn else None
        if formatted_asn:
            candidates.append(
                DiscoveryCandidate(
                    asset_type=AssetType.asn,
                    value=formatted_asn,
                    relationship_type=RelationshipType.announced_by,
                    confidence=_ASN_CANDIDATE_CONFIDENCE,
                    evidence={
                        "source": "team_cymru_origin",
                        "observed_from": seed_value,
                        "announced_prefix": announced_prefix,
                        "network_country": network_country,
                        "registry": registry,
                        "asn_organization": asn_organization,
                    },
                )
            )

        network_data = NetworkObservation(
            ip=seed_value,
            ip_version=ip.version,
            asn=formatted_asn,
            asn_organization=asn_organization,
            announced_prefix=announced_prefix,
            network_country=network_country,
            registry=registry,
            ptr_hostname=ptr_hostname,
            cloud_provider_evidence=cloud_provider_evidence,
            confidence=_ASN_CANDIDATE_CONFIDENCE if formatted_asn else _PARTIAL_RESULT_CONFIDENCE,
        )

        return DiscoveryProviderResult(provider=self.name, candidates=candidates, network_data=network_data)

    def _query_origin(self, resolver: "dns.resolver.Resolver", ip) -> dict | None:
        """Never raises -- an expected DNS outcome (no data for this
        address, timeout, no nameservers) or a malformed/unexpected
        response both collapse to "no origin data," mirroring
        dns_provider.py's own _resolve contract exactly.
        """
        query_name = _cymru_origin_query_name(ip)
        try:
            answer = resolver.resolve(query_name, "TXT")
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            dns.exception.Timeout,
        ):
            return None
        except Exception:
            return None

        try:
            fields = _parse_pipe_fields(answer[0].to_text())
            if len(fields) < 3:
                return None
            # AS field can rarely carry multiple space-separated ASNs
            # for a multi-origin-AS prefix -- take the first, the
            # common/unambiguous case, rather than guess which applies.
            asn = fields[0].split()[0] if fields[0].split() else None
            if not asn or not asn.isdigit():
                return None
            return {"asn": asn, "prefix": fields[1] or None, "country": fields[2] or None, "registry": fields[3] if len(fields) > 3 else None}
        except Exception:
            return None

    def _query_asn_name(self, resolver: "dns.resolver.Resolver", asn: str) -> dict | None:
        try:
            answer = resolver.resolve(f"AS{asn}.asn.cymru.com", "TXT")
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            dns.exception.Timeout,
        ):
            return None
        except Exception:
            return None

        try:
            fields = _parse_pipe_fields(answer[0].to_text())
            if len(fields) < 5:
                return None
            return {"as_name": fields[4] or None}
        except Exception:
            return None

    def _query_ptr(self, resolver: "dns.resolver.Resolver", ip_str: str) -> str | None:
        try:
            reverse_name = dns.reversename.from_address(ip_str)
            answer = resolver.resolve(reverse_name, "PTR")
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            dns.exception.Timeout,
        ):
            return None
        except Exception:
            return None

        try:
            hostname = answer[0].to_text().rstrip(".")
            return hostname or None
        except Exception:
            return None

