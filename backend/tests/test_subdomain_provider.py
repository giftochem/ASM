"""Unit tests for SubdomainDiscoveryProvider — no real network. Mocks
httpx.get at the provider's own module reference, matching how DNS/
certificate provider tests isolate at their respective external-call
boundaries (dns.resolver.Resolver.resolve / socket.create_connection).
"""

import httpx
import pytest

import app.discovery.subdomain_provider as subdomain_provider_module
from app.core.enums import AssetType, RelationshipType
from app.discovery.subdomain_provider import SubdomainDiscoveryProvider


class _FakeResponse:
    def __init__(self, json_data=None, status_code=200, json_error=False):
        self._json_data = json_data
        self.status_code = status_code
        self._json_error = json_error

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError("error", request=None, response=self)

    def json(self):
        if self._json_error:
            raise ValueError("simulated malformed JSON")
        return self._json_data


def _patch_response(monkeypatch, response=None, exception=None):
    def _fake_get(url, params=None, timeout=None):
        if exception is not None:
            raise exception
        return response

    monkeypatch.setattr(subdomain_provider_module.httpx, "get", _fake_get)


def _entry(name_value: str) -> dict:
    return {"name_value": name_value}


def test_provider_supports_domain_and_subdomain_only():
    provider = SubdomainDiscoveryProvider()
    assert provider.supports(AssetType.domain) is True
    assert provider.supports(AssetType.subdomain) is True
    assert provider.supports(AssetType.ip_address) is False


def test_normal_response_creates_in_scope_candidates(monkeypatch):
    _patch_response(monkeypatch, _FakeResponse([_entry("api.example.com\nwww.example.com")]))

    result = SubdomainDiscoveryProvider().discover("example.com")

    assert result.error is None
    values = sorted(c.value for c in result.candidates)
    assert values == ["api.example.com", "www.example.com"]
    for candidate in result.candidates:
        assert candidate.asset_type == AssetType.subdomain
        assert candidate.relationship_type == RelationshipType.belongs_to
        assert candidate.confidence == 0.6


def test_wildcard_names_excluded_from_candidates(monkeypatch):
    _patch_response(monkeypatch, _FakeResponse([_entry("*.example.com\napi.example.com")]))

    result = SubdomainDiscoveryProvider().discover("example.com")

    values = [c.value for c in result.candidates]
    assert "*.example.com" not in values
    assert "api.example.com" in values
    assert "*.example.com" in result.seed_evidence["wildcard_names"]


def test_duplicate_and_case_variant_names_collapsed(monkeypatch):
    _patch_response(
        monkeypatch,
        _FakeResponse(
            [
                _entry("API.example.com"),
                _entry("api.example.com"),
                _entry("api.example.com."),  # trailing dot
                _entry("api.example.com\napi.example.com"),
            ]
        ),
    )

    result = SubdomainDiscoveryProvider().discover("example.com")

    assert len(result.candidates) == 1
    assert result.candidates[0].value == "api.example.com"


def test_seed_itself_never_becomes_a_candidate(monkeypatch):
    _patch_response(monkeypatch, _FakeResponse([_entry("example.com\napi.example.com")]))

    result = SubdomainDiscoveryProvider().discover("example.com")

    values = [c.value for c in result.candidates]
    assert "example.com" not in values
    assert "api.example.com" in values


@pytest.mark.parametrize(
    "external_name",
    [
        "evil-example.com",
        "example.com.evil.com",
        "example.net",
        "foo.example.com.evil.net",
    ],
)
def test_out_of_scope_names_become_evidence_not_candidates(monkeypatch, external_name):
    _patch_response(monkeypatch, _FakeResponse([_entry(f"api.example.com\n{external_name}")]))

    result = SubdomainDiscoveryProvider().discover("example.com")

    values = [c.value for c in result.candidates]
    assert external_name not in values
    assert external_name in result.seed_evidence["external_names"]


def test_malformed_entry_does_not_abort_batch(monkeypatch):
    _patch_response(
        monkeypatch,
        _FakeResponse(
            [
                {"name_value": None},  # .split() on None would raise -- must not abort the batch
                "not a dict at all",
                _entry("api.example.com"),
            ]
        ),
    )

    result = SubdomainDiscoveryProvider().discover("example.com")

    assert result.error is None
    assert [c.value for c in result.candidates] == ["api.example.com"]


def test_empty_response_produces_no_candidates_no_error(monkeypatch):
    _patch_response(monkeypatch, _FakeResponse([]))

    result = SubdomainDiscoveryProvider().discover("example.com")

    assert result.error is None
    assert result.candidates == []


def test_http_error_handled_cleanly(monkeypatch):
    _patch_response(monkeypatch, exception=httpx.ConnectError("simulated connection failure"))

    result = SubdomainDiscoveryProvider().discover("example.com")

    assert result.error is not None
    assert result.candidates == []


def test_timeout_handled_cleanly(monkeypatch):
    _patch_response(monkeypatch, exception=httpx.TimeoutException("simulated timeout"))

    result = SubdomainDiscoveryProvider().discover("example.com")

    assert result.error is not None
    assert "timeout" in result.error.lower() or "simulated" in result.error.lower()


def test_rate_limited_response_handled_cleanly(monkeypatch):
    _patch_response(monkeypatch, _FakeResponse(status_code=429))

    result = SubdomainDiscoveryProvider().discover("example.com")

    assert result.error is not None
    assert result.candidates == []


def test_malformed_json_handled_cleanly(monkeypatch):
    _patch_response(monkeypatch, _FakeResponse(json_error=True))

    result = SubdomainDiscoveryProvider().discover("example.com")

    assert result.error is not None


def test_unexpected_response_shape_handled_cleanly(monkeypatch):
    """crt.sh returning something that isn't a JSON array (e.g. an error
    page's HTML happened to parse as a JSON object/string) must not
    crash the provider.
    """
    _patch_response(monkeypatch, _FakeResponse({"unexpected": "shape"}))

    result = SubdomainDiscoveryProvider().discover("example.com")

    assert result.error is not None
    assert result.candidates == []


def test_max_raw_entries_cap_applied(monkeypatch):
    entries = [_entry(f"host{i}.example.com") for i in range(subdomain_provider_module._MAX_RAW_ENTRIES + 50)]
    _patch_response(monkeypatch, _FakeResponse(entries))

    result = SubdomainDiscoveryProvider().discover("example.com")

    assert result.seed_evidence["raw_entries_processed"] == subdomain_provider_module._MAX_RAW_ENTRIES


def test_max_candidate_hostnames_cap_applied(monkeypatch):
    cap = subdomain_provider_module._MAX_CANDIDATE_HOSTNAMES
    entries = [_entry(f"host{i}.example.com") for i in range(cap + 25)]
    _patch_response(monkeypatch, _FakeResponse(entries))

    result = SubdomainDiscoveryProvider().discover("example.com")

    assert len(result.candidates) == cap
    assert result.seed_evidence["candidate_names_truncated"] is True


def test_seed_evidence_change_type_is_certificate_transparency(monkeypatch):
    from app.core.enums import ChangeType

    _patch_response(monkeypatch, _FakeResponse([_entry("api.example.com")]))

    result = SubdomainDiscoveryProvider().discover("example.com")

    assert result.seed_evidence_change_type == ChangeType.certificate_transparency_observed
