"""Passive hostname discovery via public Certificate Transparency logs
(crt.sh) -- discovers hostnames an authorized domain/subdomain seed has
had a certificate issued for, at any point in the past.

CT is a historical record, not a liveness check: a hostname appearing
here means "a certificate naming this hostname was logged," never "this
host is currently reachable." Confidence (0.6) is set deliberately lower
than any other provider in this system -- DNS resolution (1.0) confirms
a name resolves right now; even a certificate SAN retrieved live by
app.discovery.certificate_provider (0.7) came from a cert this codebase
itself just verified still exists. A CT log entry confirms neither.

Deliberately NOT routed through app.scanners.net_safety/pinned_transport:
those exist to protect against a connection destination *controlled by
the scan target* (SSRF) -- DNS/certificate discovery connect to
something derived from the seed itself. Here the connection destination
is always the fixed, trusted host crt.sh; the seed domain is only a
query-string parameter, never a connection target, so that threat model
doesn't apply. This provider never opens a connection to anything it
discovers -- the one and only network call it ever makes is the single
crt.sh query below.

crt.sh's own search matching is loose (substring-style) and is NOT
trusted as a scope boundary -- every single result, regardless of why
crt.sh returned it, is independently re-verified via
app.core.validation.is_hostname_in_scope before it can become a
candidate.
"""

import httpx

from app.core.enums import AssetType, ChangeType, RelationshipType
from app.core.validation import is_hostname_in_scope, normalize_hostname
from app.discovery.base import DiscoveryCandidate, DiscoveryProvider, DiscoveryProviderResult

_CT_SEARCH_URL = "https://crt.sh/"
_HTTP_TIMEOUT_SECONDS = 10.0  # crt.sh is shared public infrastructure -- slower than this system's other lookups
_MAX_RAW_ENTRIES = 2000  # how many crt.sh response rows get parsed at all -- a popular domain's CT history is huge
_MAX_CANDIDATE_HOSTNAMES = 200  # hard ceiling on unique in-scope names turned into candidates in one run
_CANDIDATE_CONFIDENCE = 0.6  # see module docstring -- the weakest evidence tier in this system so far


class SubdomainDiscoveryProvider(DiscoveryProvider):
    name = "subdomain"
    applicable_seed_types = {AssetType.domain, AssetType.subdomain}

    def discover(self, seed_value: str) -> DiscoveryProviderResult:
        try:
            response = httpx.get(
                _CT_SEARCH_URL, params={"q": seed_value, "output": "json"}, timeout=_HTTP_TIMEOUT_SECONDS
            )
            response.raise_for_status()
            entries = response.json()
        except Exception as exc:
            return DiscoveryProviderResult(
                provider=self.name,
                error=f"certificate transparency query failed for '{seed_value}': {exc}",
            )

        if not isinstance(entries, list):
            return DiscoveryProviderResult(
                provider=self.name, error="unexpected certificate transparency response shape"
            )

        raw_names: set[str] = set()
        for entry in entries[:_MAX_RAW_ENTRIES]:
            # One malformed entry must not abort the whole batch.
            try:
                name_value = entry.get("name_value", "") if isinstance(entry, dict) else ""
                for raw_name in name_value.split("\n"):
                    normalized = normalize_hostname(raw_name)
                    if normalized:
                        raw_names.add(normalized)
            except Exception:
                continue

        candidates: list[DiscoveryCandidate] = []
        wildcard_names: list[str] = []
        external_names: list[str] = []
        truncated = False

        for name in sorted(raw_names):
            try:
                if name == seed_value:
                    continue  # the seed's own name, already tracked as the seed asset
                if name.startswith("*."):
                    # A wildcard isn't a real, connectable hostname --
                    # evidence only, never a candidate asset (per the
                    # explicit instruction: *.example.com must not become
                    # an asset).
                    wildcard_names.append(name)
                    continue
                if not is_hostname_in_scope(name, seed_value):
                    external_names.append(name)
                    continue
                if len(candidates) >= _MAX_CANDIDATE_HOSTNAMES:
                    truncated = True
                    continue
                candidates.append(
                    DiscoveryCandidate(
                        asset_type=AssetType.subdomain,
                        value=name,
                        relationship_type=RelationshipType.belongs_to,
                        confidence=_CANDIDATE_CONFIDENCE,
                        evidence={"source": "certificate_transparency", "observed_from": seed_value},
                    )
                )
            except Exception:
                continue

        seed_evidence = {
            "certificate_transparency_source": "crt.sh",
            "raw_entries_processed": min(len(entries), _MAX_RAW_ENTRIES),
            "unique_names_found": len(raw_names),
            "wildcard_names": wildcard_names,
            "external_names": external_names,
            "candidate_names_truncated": truncated,
        }

        return DiscoveryProviderResult(
            provider=self.name,
            candidates=candidates,
            seed_evidence=seed_evidence,
            seed_evidence_change_type=ChangeType.certificate_transparency_observed,
        )
