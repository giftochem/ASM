"""Pure, provider-agnostic cloud/infrastructure classification (Step
9.7). Takes whatever signals are available (some may be missing) and
produces a confidence-scored provider attribution with an explicit
evidence trail -- no I/O of its own, so every combination of signals is
directly unit-testable without mocking anything.

DESIGN: multiple corroborating weak/moderate signals, not one strong
"authoritative" source. Provider-published IP range lists (e.g. AWS's
ip-ranges.json, Cloudflare's published CIDR blocks) were considered and
deliberately deferred -- fetching, caching, and periodically refreshing
those lists is a real, separate subsystem (mirrors the Step 9.4
decision to defer a "DNS second source" as requiring substantial new
architecture), not something to bolt on speculatively here. Because
this classification never has an authoritative range match to lean on,
overall confidence is capped below "certain" (see _MAX_CONFIDENCE) --
an honest reflection of what evidence this pass actually has access to.

Each signal type has its own weight, reflecting how hard it is to
spoof/misconfigure: an ASN (either its number or its registered
organization name) is infrastructure-level and hardest to fake; a PTR
record is DNS-level, set by whoever controls the address block; an HTTP
Server header or TLS issuer are still meaningful but easier to obscure
or coincidentally share (e.g. Let's Encrypt is deliberately excluded as
a TLS-issuer signal -- anyone can use it, on any infrastructure, so it
carries zero provider information).

CONFLICTING SIGNALS: when two providers each accumulate meaningfully
comparable evidence (the runner-up's score is at least 60% of the
winner's), `conflicting=True` is set and the runner-up is preserved in
`alternative_providers` -- the caller is expected to record and surface
both, never silently pick the higher score and hide the disagreement.

WHY THERE IS NO SEPARATE "ANNOUNCED PREFIX" SIGNAL: the prefix and the
ASN both come from the exact same Team Cymru origin-lookup response --
they are not independent observations, just two facets of one fact
("this address falls within this prefix, which this ASN announces").
Weighting prefix membership as a second, separate vote for the same
provider the ASN already voted for would double-count that one fact,
inflating confidence without adding real corroboration. The prefix is
still recorded as descriptive evidence and still participates in change
detection (a prefix change is meaningful even when the ASN doesn't
change) -- it just isn't its own classification signal here.

WHY THERE IS NO IP-RANGE-LIST SIGNAL: see the module docstring above --
deliberately deferred, not a hardcoded (and inevitably stale) guess at
providers' published CIDR blocks.
"""

import re
from dataclasses import dataclass, field

_MAX_CONFIDENCE = 0.9

_SIGNAL_WEIGHTS = {
    "asn_number": 0.55,
    "asn_organization": 0.45,
    "tls_issuer": 0.35,
    "ptr_hostname": 0.30,
    "http_server": 0.25,
}

# A small, intentionally incomplete table of well-known PRIMARY ASNs for
# a handful of major providers -- not exhaustive (each of these
# providers operates many ASNs in reality). An unmatched, genuinely
# provider-owned ASN simply falls through to the (still useful, lower-
# weighted) organization-name signal below rather than asserting a false
# negative.
_KNOWN_PROVIDER_ASNS = {
    "AS16509": "Amazon Web Services",
    "AS14618": "Amazon Web Services",
    "AS8075": "Microsoft Azure",
    "AS15169": "Google Cloud",
    "AS396982": "Google Cloud",
    "AS13335": "Cloudflare",
    "AS14061": "DigitalOcean",
    "AS31898": "Oracle Cloud",
    "AS20940": "Akamai",
    "AS16625": "Akamai",
    "AS54113": "Fastly",
    "AS24940": "Hetzner",
    "AS16276": "OVH",
    "AS63949": "Linode",
}

# Per provider, per signal type: patterns that -- if they match the
# corresponding raw signal string -- count as evidence for that
# provider. An empty list means "no reliable pattern for this signal
# type," not "not applicable" -- e.g. Cloudflare-fronted origins rarely
# expose a distinctive PTR, since the visible IP is Cloudflare's edge,
# not the origin's own address block.
_PROVIDER_SIGNATURES: dict[str, dict[str, list[re.Pattern]]] = {
    "Amazon Web Services": {
        "asn_organization": [re.compile(r"AMAZON|\bAWS\b", re.I)],
        "ptr_hostname": [re.compile(r"\.amazonaws\.com\.?$", re.I)],
        "http_server": [re.compile(r"AmazonS3|CloudFront", re.I)],
        "tls_issuer": [re.compile(r"\bAmazon\b", re.I)],
    },
    "Microsoft Azure": {
        "asn_organization": [re.compile(r"MICROSOFT|AZURE", re.I)],
        "ptr_hostname": [re.compile(r"\.cloudapp\.(azure\.com|net)\.?$", re.I)],
        "http_server": [],
        "tls_issuer": [re.compile(r"Microsoft", re.I)],
    },
    "Google Cloud": {
        "asn_organization": [re.compile(r"GOOGLE", re.I)],
        "ptr_hostname": [re.compile(r"\.googleusercontent\.com\.?$", re.I), re.compile(r"\.bc\.googleusercontent\.com\.?$", re.I)],
        "http_server": [re.compile(r"^gws$|Google Frontend", re.I)],
        "tls_issuer": [re.compile(r"Google Trust Services|\bGTS\b", re.I)],
    },
    "Cloudflare": {
        "asn_organization": [re.compile(r"CLOUDFLARE", re.I)],
        "ptr_hostname": [],
        "http_server": [re.compile(r"^cloudflare$", re.I)],
        "tls_issuer": [re.compile(r"Cloudflare", re.I)],
    },
    "DigitalOcean": {
        "asn_organization": [re.compile(r"DIGITALOCEAN", re.I)],
        "ptr_hostname": [],
        "http_server": [],
        "tls_issuer": [],
    },
    "Oracle Cloud": {
        "asn_organization": [re.compile(r"ORACLE", re.I)],
        "ptr_hostname": [re.compile(r"\.oraclecloud\.com\.?$", re.I)],
        "http_server": [],
        "tls_issuer": [],
    },
    "Akamai": {
        "asn_organization": [re.compile(r"AKAMAI", re.I)],
        "ptr_hostname": [re.compile(r"\.akamai(edge|technologies)?\.net\.?$", re.I)],
        "http_server": [re.compile(r"AkamaiGHost", re.I)],
        "tls_issuer": [],
    },
    "Fastly": {
        "asn_organization": [re.compile(r"FASTLY", re.I)],
        "ptr_hostname": [],
        "http_server": [re.compile(r"^fastly$", re.I)],
        "tls_issuer": [],
    },
    "Hetzner": {
        "asn_organization": [re.compile(r"HETZNER", re.I)],
        "ptr_hostname": [re.compile(r"\.your-server\.de\.?$", re.I)],
        "http_server": [],
        "tls_issuer": [],
    },
    "OVH": {
        "asn_organization": [re.compile(r"\bOVH\b", re.I)],
        "ptr_hostname": [re.compile(r"\.ovh\.(net|com)\.?$", re.I)],
        "http_server": [],
        "tls_issuer": [],
    },
    "Linode": {
        "asn_organization": [re.compile(r"LINODE", re.I)],
        "ptr_hostname": [re.compile(r"\.linode\.com\.?$", re.I), re.compile(r"\.members\.linode\.com\.?$", re.I)],
        "http_server": [],
        "tls_issuer": [],
    },
}

# Issuers that provide zero provider information because anyone, on any
# infrastructure, can obtain a certificate from them -- must never be
# treated as evidence for (or against) a specific cloud provider.
_GENERIC_CA_ISSUERS = (
    re.compile(r"Let'?s Encrypt", re.I),
    re.compile(r"ZeroSSL", re.I),
    re.compile(r"DigiCert", re.I),  # sold broadly across every provider, not provider-specific
    re.compile(r"Sectigo|Comodo", re.I),
)


def confidence_label(confidence: float) -> str:
    if confidence >= 0.75:
        return "confidently_identified"
    if confidence >= 0.5:
        return "probably_identified"
    if confidence > 0:
        return "weakly_inferred"
    return "unknown"


@dataclass
class InfrastructureClassification:
    provider: str | None
    confidence: float
    evidence: list[dict] = field(default_factory=list)
    conflicting: bool = False
    alternative_providers: list[dict] = field(default_factory=list)

    @property
    def confidence_label(self) -> str:
        return confidence_label(self.confidence)


def classify_infrastructure(
    *,
    asn: str | None = None,
    asn_organization: str | None = None,
    ptr_hostname: str | None = None,
    http_server: str | None = None,
    tls_issuer: str | None = None,
) -> InfrastructureClassification:
    """Every parameter is optional -- a caller passes whatever it has.
    Missing/None signals simply contribute nothing; this never raises.
    """
    scores: dict[str, float] = {}
    evidence_by_provider: dict[str, list[dict]] = {}

    def _add(provider_name: str, signal_name: str, detail: str) -> None:
        scores[provider_name] = scores.get(provider_name, 0.0) + _SIGNAL_WEIGHTS[signal_name]
        evidence_by_provider.setdefault(provider_name, []).append({"signal": signal_name, "detail": detail})

    if asn:
        known_provider = _KNOWN_PROVIDER_ASNS.get(asn.upper())
        if known_provider:
            _add(known_provider, "asn_number", f"{asn} is a known primary ASN for {known_provider}")

    if tls_issuer and any(p.search(tls_issuer) for p in _GENERIC_CA_ISSUERS):
        tls_issuer = None  # a generic CA proves nothing about the underlying infrastructure

    raw_signals = {"asn_organization": asn_organization, "ptr_hostname": ptr_hostname, "http_server": http_server, "tls_issuer": tls_issuer}
    for provider_name, signal_patterns in _PROVIDER_SIGNATURES.items():
        for signal_name, patterns in signal_patterns.items():
            value = raw_signals.get(signal_name)
            if not value:
                continue
            for pattern in patterns:
                if pattern.search(value):
                    _add(provider_name, signal_name, f"{signal_name} matched '{pattern.pattern}' for {provider_name}")
                    break  # one match per (provider, signal type) is enough

    if not scores:
        return InfrastructureClassification(provider=None, confidence=0.0, evidence=[])

    ranked = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
    top_provider, top_score = ranked[0]
    conflicting = len(ranked) > 1 and ranked[1][1] >= top_score * 0.6

    return InfrastructureClassification(
        provider=top_provider,
        confidence=min(top_score, _MAX_CONFIDENCE),
        evidence=evidence_by_provider[top_provider],
        conflicting=conflicting,
        alternative_providers=[
            {"provider": name, "confidence": min(score, _MAX_CONFIDENCE), "evidence": evidence_by_provider[name]}
            for name, score in ranked[1:]
        ],
    )
