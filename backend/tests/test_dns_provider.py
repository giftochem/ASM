"""Unit tests for DNSDiscoveryProvider — no network. dns.resolver.Resolver.resolve
is monkeypatched directly (the same call app.scanners.dns_module makes),
so these tests exercise the real provider code against deterministic,
canned responses.
"""

import dns.exception
import dns.resolver
import pytest

from app.core.enums import AssetType, RelationshipType
from app.discovery.dns_provider import DNSDiscoveryProvider


class _FakeRdata:
    def __init__(self, text: str):
        self._text = text

    def to_text(self) -> str:
        return self._text


class _FakeRRset:
    def __init__(self, ttl: int = 300):
        self.ttl = ttl


class _FakeAnswer(list):
    def __init__(self, values: list[str]):
        super().__init__(_FakeRdata(v) for v in values)
        self.rrset = _FakeRRset()


def _install_fake_resolver(monkeypatch, responses: dict[str, list[str] | Exception]):
    """`responses` maps record type ("A", "MX", ...) to either a list of
    to_text()-shaped strings, or an exception instance to raise.
    """

    def _fake_resolve(self, name, rdtype, *args, **kwargs):
        response = responses.get(rdtype, dns.resolver.NoAnswer())
        if isinstance(response, Exception):
            raise response
        return _FakeAnswer(response)

    monkeypatch.setattr(dns.resolver.Resolver, "resolve", _fake_resolve)


def test_provider_supports_domain_and_subdomain_only():
    provider = DNSDiscoveryProvider()
    assert provider.supports(AssetType.domain) is True
    assert provider.supports(AssetType.subdomain) is True
    assert provider.supports(AssetType.ip_address) is False


def test_a_and_aaaa_records_become_ip_candidates_with_resolves_to(monkeypatch):
    _install_fake_resolver(
        monkeypatch,
        {"A": ["93.184.216.34"], "AAAA": ["2606:2800:220:1:248:1893:25c8:1946"]},
    )
    result = DNSDiscoveryProvider().discover("example.com")

    ip_candidates = [c for c in result.candidates if c.asset_type == AssetType.ip_address]
    assert {c.value for c in ip_candidates} == {"93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"}
    assert all(c.relationship_type == RelationshipType.resolves_to for c in ip_candidates)
    assert all(c.confidence == 1.0 for c in ip_candidates)


def test_in_scope_cname_becomes_subdomain_candidate(monkeypatch):
    _install_fake_resolver(monkeypatch, {"CNAME": ["edge.example.com."]})
    result = DNSDiscoveryProvider().discover("example.com")

    assert len(result.candidates) == 1
    candidate = result.candidates[0]
    assert candidate.asset_type == AssetType.subdomain
    assert candidate.value == "edge.example.com"
    assert candidate.relationship_type == RelationshipType.resolves_to


def test_out_of_scope_cname_becomes_seed_evidence_not_a_candidate(monkeypatch):
    _install_fake_resolver(monkeypatch, {"CNAME": ["d111.cloudfront.net."]})
    result = DNSDiscoveryProvider().discover("app.example.com")

    assert result.candidates == []
    assert result.seed_evidence is not None
    assert result.seed_evidence["out_of_scope_targets"]["cname"] == ["d111.cloudfront.net"]


def test_in_scope_mx_becomes_subdomain_candidate_with_uses(monkeypatch):
    _install_fake_resolver(monkeypatch, {"MX": ["10 mail.example.com."]})
    result = DNSDiscoveryProvider().discover("example.com")

    assert len(result.candidates) == 1
    candidate = result.candidates[0]
    assert candidate.value == "mail.example.com"
    assert candidate.relationship_type == RelationshipType.uses


def test_out_of_scope_mx_becomes_seed_evidence(monkeypatch):
    _install_fake_resolver(monkeypatch, {"MX": ["10 aspmx.l.google.com."]})
    result = DNSDiscoveryProvider().discover("example.com")

    assert result.candidates == []
    assert result.seed_evidence["out_of_scope_targets"]["mx"] == ["aspmx.l.google.com"]


def test_in_scope_ns_becomes_subdomain_candidate_with_served_by(monkeypatch):
    _install_fake_resolver(monkeypatch, {"NS": ["ns1.example.com."]})
    result = DNSDiscoveryProvider().discover("example.com")

    assert len(result.candidates) == 1
    candidate = result.candidates[0]
    assert candidate.value == "ns1.example.com"
    assert candidate.relationship_type == RelationshipType.served_by


def test_out_of_scope_ns_becomes_seed_evidence(monkeypatch):
    _install_fake_resolver(monkeypatch, {"NS": ["ns1.registrar-dns.com."]})
    result = DNSDiscoveryProvider().discover("example.com")

    assert result.candidates == []
    assert result.seed_evidence["out_of_scope_targets"]["ns"] == ["ns1.registrar-dns.com"]


def test_txt_records_never_become_candidates_always_seed_evidence(monkeypatch):
    _install_fake_resolver(monkeypatch, {"TXT": ['"v=spf1 include:_spf.example.com ~all"']})
    result = DNSDiscoveryProvider().discover("example.com")

    assert result.candidates == []
    assert result.seed_evidence["txt_records"] == ['"v=spf1 include:_spf.example.com ~all"']


def test_nxdomain_handled_cleanly_with_no_candidates_and_no_error(monkeypatch):
    _install_fake_resolver(
        monkeypatch,
        {rt: dns.resolver.NXDOMAIN() for rt in ("A", "AAAA", "CNAME", "MX", "NS", "TXT")},
    )
    result = DNSDiscoveryProvider().discover("does-not-exist.example.com")

    assert result.error is None
    assert result.candidates == []
    assert result.seed_evidence is None


def test_dns_timeout_on_one_record_type_does_not_abort_the_run(monkeypatch):
    _install_fake_resolver(
        monkeypatch,
        {"A": dns.exception.Timeout(), "AAAA": ["2606:2800:220:1:248:1893:25c8:1946"]},
    )
    result = DNSDiscoveryProvider().discover("example.com")

    assert result.error is None
    assert len(result.candidates) == 1
    assert result.candidates[0].value == "2606:2800:220:1:248:1893:25c8:1946"


def test_servfail_handled_cleanly(monkeypatch):
    _install_fake_resolver(monkeypatch, {"A": dns.resolver.NoNameservers()})
    result = DNSDiscoveryProvider().discover("example.com")

    assert result.error is None
    assert result.candidates == []


def test_malformed_response_handled_cleanly(monkeypatch):
    """Simulates a resolver response that raises something unexpected
    while being iterated/parsed -- proves the broad safety net, not just
    the specific dnspython exception classes.
    """

    class _BrokenAnswer:
        def __iter__(self):
            raise ValueError("simulated malformed DNS response")

    def _fake_resolve(self, name, rdtype, *args, **kwargs):
        if rdtype == "A":
            return _BrokenAnswer()
        raise dns.resolver.NoAnswer()

    monkeypatch.setattr(dns.resolver.Resolver, "resolve", _fake_resolve)

    result = DNSDiscoveryProvider().discover("example.com")
    assert result.error is None
    assert result.candidates == []


def test_no_records_at_all_produces_no_candidates_no_evidence_no_error(monkeypatch):
    _install_fake_resolver(monkeypatch, {})
    result = DNSDiscoveryProvider().discover("quiet.example.com")

    assert result.error is None
    assert result.candidates == []
    assert result.seed_evidence is None


@pytest.mark.parametrize(
    "candidate,seed,expected",
    [
        ("api.example.com", "example.com", True),
        ("foo.api.example.com", "api.example.com", True),
        ("evil-example.com", "example.com", False),
        ("example.com.evil.com", "example.com", False),
    ],
)
def test_scope_boundary_cases_reflected_in_provider_output(monkeypatch, candidate, seed, expected):
    _install_fake_resolver(monkeypatch, {"NS": [f"{candidate}."]})
    result = DNSDiscoveryProvider().discover(seed)

    if expected:
        assert len(result.candidates) == 1
        assert result.candidates[0].value == candidate
    else:
        assert result.candidates == []
        assert result.seed_evidence["out_of_scope_targets"]["ns"] == [candidate]
