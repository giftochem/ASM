"""Passive DNS intelligence -- resolves exactly the seed name's own
A/AAAA/CNAME/MX/NS/TXT records: 6 bounded, sequential queries against
ONE name, mirroring app.scanners.dns_module's resolver usage and
exception handling exactly (dnspython is already a dependency; nothing
new was added). Never guesses subdomain names, never recurses into
whatever it discovers, never attempts a zone transfer.

Every discovered hostname is checked against the seed's authorized
scope via app.core.validation.is_hostname_in_scope before it can become
a candidate -- an out-of-scope CNAME/MX/NS target (e.g. a third-party
mail or CDN provider) is recorded as evidence on the seed instead, never
as a new Asset. TXT records are never candidates at all, only evidence
-- see the module docstring on DiscoveryProviderResult.seed_evidence.
"""

import dns.exception
import dns.resolver

from app.core.enums import AssetType, RelationshipType
from app.core.validation import is_hostname_in_scope, normalize_hostname
from app.discovery.base import DiscoveryCandidate, DiscoveryProvider, DiscoveryProviderResult

_LOOKUP_TIMEOUT_SECONDS = 5.0
_CONFIDENCE = 1.0  # directly resolved via a trusted resolver, not inferred


class DNSDiscoveryProvider(DiscoveryProvider):
    name = "dns"
    applicable_seed_types = {AssetType.domain, AssetType.subdomain}

    def discover(self, seed_value: str) -> DiscoveryProviderResult:
        resolver = dns.resolver.Resolver()
        resolver.timeout = _LOOKUP_TIMEOUT_SECONDS
        resolver.lifetime = _LOOKUP_TIMEOUT_SECONDS

        candidates: list[DiscoveryCandidate] = []
        out_of_scope: dict[str, list[str]] = {}

        for record_type in ("A", "AAAA"):
            for value in self._resolve(resolver, seed_value, record_type):
                candidates.append(
                    DiscoveryCandidate(
                        asset_type=AssetType.ip_address,
                        value=value,
                        relationship_type=RelationshipType.resolves_to,
                        confidence=_CONFIDENCE,
                        evidence={"record_type": record_type, "name": seed_value},
                    )
                )

        for value in self._resolve(resolver, seed_value, "CNAME"):
            self._handle_hostname_target(
                candidates, out_of_scope, "cname", value, seed_value, RelationshipType.resolves_to
            )

        for value in self._resolve(resolver, seed_value, "MX"):
            # dnspython's to_text() for MX is "<preference> <exchange>.",
            # e.g. "10 mail.example.com." -- the hostname is the last token.
            hostname = value.split()[-1] if value.strip() else ""
            self._handle_hostname_target(
                candidates, out_of_scope, "mx", hostname, seed_value, RelationshipType.uses
            )

        for value in self._resolve(resolver, seed_value, "NS"):
            self._handle_hostname_target(
                candidates, out_of_scope, "ns", value, seed_value, RelationshipType.served_by
            )

        txt_values = self._resolve(resolver, seed_value, "TXT")

        seed_evidence: dict = {}
        if txt_values:
            seed_evidence["txt_records"] = txt_values
        if out_of_scope:
            seed_evidence["out_of_scope_targets"] = out_of_scope

        return DiscoveryProviderResult(
            provider=self.name,
            candidates=candidates,
            seed_evidence=seed_evidence or None,
        )

    def _resolve(self, resolver: "dns.resolver.Resolver", name: str, record_type: str) -> list[str]:
        """Never raises -- an expected DNS outcome (no such name, no
        records of this type, timeout, no nameservers available) or an
        unexpected/malformed response both collapse to "no results for
        this record type," so one bad lookup can't take down the other
        5 or the whole discovery run.
        """
        try:
            answer = resolver.resolve(name, record_type)
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            dns.exception.Timeout,
        ):
            return []
        except Exception:
            return []

        try:
            return [rdata.to_text() for rdata in answer]
        except Exception:
            return []

    def _handle_hostname_target(
        self,
        candidates: list[DiscoveryCandidate],
        out_of_scope: dict[str, list[str]],
        record_type: str,
        raw_value: str,
        seed_value: str,
        relationship_type: RelationshipType,
    ) -> None:
        if not raw_value.strip():
            return
        target = normalize_hostname(raw_value.rstrip("."))
        if not target:
            return

        if is_hostname_in_scope(target, seed_value):
            candidates.append(
                DiscoveryCandidate(
                    asset_type=AssetType.subdomain,
                    value=target,
                    relationship_type=relationship_type,
                    confidence=_CONFIDENCE,
                    evidence={"record_type": record_type.upper(), "name": seed_value},
                )
            )
        else:
            out_of_scope.setdefault(record_type, []).append(target)
