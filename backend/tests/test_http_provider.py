"""Unit tests for HttpDiscoveryProvider — no real network. Mocks
app.scanners.http_client.fetch_url at the provider's own module
reference, matching how DNS/certificate/subdomain provider tests
isolate at their respective external-call boundaries. SSRF/redirect
safety proofs (including one real, unmocked test) live in
test_http_provider_ssrf.py instead of here.
"""

import app.discovery.http_provider as http_provider_module
from app.core.enums import AssetType
from app.discovery.http_provider import HttpDiscoveryProvider
from app.scanners.http_client import FetchError, FetchResult


def _result(**overrides) -> FetchResult:
    defaults = dict(
        final_url="https://example.com/",
        status_code=200,
        headers={},
        text="",
        truncated=False,
        redirect_count=0,
        set_cookie_headers=[],
    )
    defaults.update(overrides)
    return FetchResult(**defaults)


def _patch_fetch(monkeypatch, mapping: dict):
    """`mapping` keys are requested URLs; values are FetchResult/FetchError
    or an Exception instance to raise.
    """

    def _fake(url, _transport=None):
        outcome = mapping[url]
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    monkeypatch.setattr(http_provider_module.http_client, "fetch_url", _fake)


def test_provider_supports_domain_subdomain_and_url_only():
    provider = HttpDiscoveryProvider()
    assert provider.supports(AssetType.domain) is True
    assert provider.supports(AssetType.subdomain) is True
    assert provider.supports(AssetType.url) is True
    assert provider.supports(AssetType.ip_address) is False


def test_bare_host_seed_attempts_both_schemes_independently(monkeypatch):
    _patch_fetch(
        monkeypatch,
        {
            "https://example.com/": _result(final_url="https://example.com/", status_code=200),
            "http://example.com/": _result(final_url="http://example.com/", status_code=301),
        },
    )

    result = HttpDiscoveryProvider().discover("example.com")

    assert result.error is None
    by_scheme = {obs.scheme: obs for obs in result.http_observations}
    assert set(by_scheme) == {"https", "http"}
    assert by_scheme["https"].status_code == 200
    assert by_scheme["http"].status_code == 301
    assert all(obs.succeeded for obs in result.http_observations)


def test_url_seed_attempts_only_its_own_scheme_not_broadened(monkeypatch):
    calls = []

    def _fake(url, _transport=None):
        calls.append(url)
        return _result(final_url=url, status_code=200)

    monkeypatch.setattr(http_provider_module.http_client, "fetch_url", _fake)

    result = HttpDiscoveryProvider().discover("https://api.example.com/v1")

    assert calls == ["https://api.example.com/v1"]
    assert len(result.http_observations) == 1
    assert result.http_observations[0].scheme == "https"
    assert result.http_observations[0].requested_url == "https://api.example.com/v1"


def test_one_scheme_failure_does_not_affect_the_other(monkeypatch):
    _patch_fetch(
        monkeypatch,
        {
            "https://example.com/": FetchError("timed out fetching"),
            "http://example.com/": _result(final_url="http://example.com/", status_code=200),
        },
    )

    result = HttpDiscoveryProvider().discover("example.com")

    assert result.error is None
    by_scheme = {obs.scheme: obs for obs in result.http_observations}
    assert by_scheme["https"].succeeded is False
    assert "timed out" in by_scheme["https"].failure_reason
    assert by_scheme["http"].succeeded is True


def test_connection_refused_reported_as_failed_observation(monkeypatch):
    _patch_fetch(
        monkeypatch,
        {
            "https://down.example.com/": FetchError("request to 'https://down.example.com/' failed: refused"),
            "http://down.example.com/": FetchError("request to 'http://down.example.com/' failed: refused"),
        },
    )

    result = HttpDiscoveryProvider().discover("down.example.com")

    assert result.error is None
    assert all(not obs.succeeded for obs in result.http_observations)


def test_redirect_recorded_with_final_url_and_count(monkeypatch):
    _patch_fetch(
        monkeypatch,
        {
            "https://example.com/": _result(
                final_url="https://www.example.com/", status_code=200, redirect_count=1
            ),
            "http://example.com/": _result(final_url="http://example.com/", status_code=200),
        },
    )

    result = HttpDiscoveryProvider().discover("example.com")

    https_obs = next(o for o in result.http_observations if o.scheme == "https")
    assert https_obs.final_url == "https://www.example.com/"
    assert https_obs.redirect_count == 1
    assert https_obs.left_authorized_scope is False  # www.example.com is in scope of example.com


def test_redirect_outside_authorized_scope_not_attributed_to_org(monkeypatch):
    _patch_fetch(
        monkeypatch,
        {
            "https://example.com/": _result(
                final_url="https://attacker-controlled.example/",
                status_code=200,
                headers={"Server": "totally-not-example-coms-server"},
                text="<title>Someone else's site</title>",
                redirect_count=1,
            ),
            "http://example.com/": _result(final_url="http://example.com/"),
        },
    )

    result = HttpDiscoveryProvider().discover("example.com")

    https_obs = next(o for o in result.http_observations if o.scheme == "https")
    assert https_obs.left_authorized_scope is True
    assert https_obs.external_redirect_host == "attacker-controlled.example"
    # The external destination's data must never be attributed to the org.
    assert https_obs.server is None
    assert https_obs.title is None
    assert https_obs.status_code is None
    assert https_obs.technology_evidence == []


def test_html_title_extracted(monkeypatch):
    html = "<html><head><title>  Example   Domain  </title></head><body></body></html>"
    _patch_fetch(
        monkeypatch,
        {
            "https://example.com/": _result(headers={"content-type": "text/html; charset=utf-8"}, text=html),
            "http://example.com/": _result(final_url="http://example.com/"),
        },
    )

    result = HttpDiscoveryProvider().discover("example.com")

    https_obs = next(o for o in result.http_observations if o.scheme == "https")
    assert https_obs.title == "Example Domain"


def test_non_html_content_type_skips_title_extraction(monkeypatch):
    _patch_fetch(
        monkeypatch,
        {
            "https://api.example.com/": _result(
                final_url="https://api.example.com/",
                headers={"content-type": "application/json"},
                text='{"title": "not a page title"}',
            ),
            "http://api.example.com/": _result(final_url="http://api.example.com/"),
        },
    )

    result = HttpDiscoveryProvider().discover("api.example.com")

    https_obs = next(o for o in result.http_observations if o.scheme == "https")
    assert https_obs.title is None
    assert https_obs.content_type == "application/json"


def test_security_headers_presence_and_absence_recorded(monkeypatch):
    _patch_fetch(
        monkeypatch,
        {
            "https://example.com/": _result(
                headers={
                    "Strict-Transport-Security": "max-age=63072000",
                    "X-Content-Type-Options": "nosniff",
                }
            ),
            "http://example.com/": _result(final_url="http://example.com/"),
        },
    )

    result = HttpDiscoveryProvider().discover("example.com")

    https_obs = next(o for o in result.http_observations if o.scheme == "https")
    assert https_obs.security_headers["strict-transport-security"] is True
    assert https_obs.security_headers["x-content-type-options"] is True
    assert https_obs.security_headers["content-security-policy"] is False
    assert https_obs.security_headers["x-frame-options"] is False
    assert https_obs.security_headers["referrer-policy"] is False
    assert https_obs.security_headers["permissions-policy"] is False


def test_server_header_produces_technology_evidence(monkeypatch):
    _patch_fetch(
        monkeypatch,
        {
            "https://example.com/": _result(headers={"Server": "nginx/1.25.0"}),
            "http://example.com/": _result(final_url="http://example.com/"),
        },
    )

    result = HttpDiscoveryProvider().discover("example.com")

    https_obs = next(o for o in result.http_observations if o.scheme == "https")
    assert https_obs.server == "nginx/1.25.0"
    assert {"technology": "nginx", "confidence": 0.8, "evidence": "Server header"} in https_obs.technology_evidence


def test_x_powered_by_produces_technology_evidence(monkeypatch):
    _patch_fetch(
        monkeypatch,
        {
            "https://example.com/": _result(headers={"X-Powered-By": "PHP/8.2.0"}),
            "http://example.com/": _result(final_url="http://example.com/"),
        },
    )

    result = HttpDiscoveryProvider().discover("example.com")

    https_obs = next(o for o in result.http_observations if o.scheme == "https")
    assert https_obs.x_powered_by == "PHP/8.2.0"
    assert {"technology": "PHP", "confidence": 0.7, "evidence": "X-Powered-By header"} in https_obs.technology_evidence


def test_generator_meta_tag_produces_weak_technology_evidence(monkeypatch):
    html = '<html><head><meta name="generator" content="React Static"></head></html>'
    _patch_fetch(
        monkeypatch,
        {
            "https://example.com/": _result(headers={"content-type": "text/html"}, text=html),
            "http://example.com/": _result(final_url="http://example.com/"),
        },
    )

    result = HttpDiscoveryProvider().discover("example.com")

    https_obs = next(o for o in result.http_observations if o.scheme == "https")
    assert {"technology": "React Static", "confidence": 0.5, "evidence": "HTML generator meta tag"} in https_obs.technology_evidence


def test_no_weak_technology_claim_without_any_indicator(monkeypatch):
    _patch_fetch(
        monkeypatch,
        {
            "https://example.com/": _result(headers={}),
            "http://example.com/": _result(final_url="http://example.com/"),
        },
    )

    result = HttpDiscoveryProvider().discover("example.com")

    https_obs = next(o for o in result.http_observations if o.scheme == "https")
    assert https_obs.technology_evidence == []


def test_set_cookie_flags_parsed_without_storing_the_value(monkeypatch):
    _patch_fetch(
        monkeypatch,
        {
            "https://example.com/": _result(
                set_cookie_headers=[
                    "sessionid=super-secret-token-value; Secure; HttpOnly; SameSite=Strict",
                    "tracking=abc123; SameSite=Lax",
                ]
            ),
            "http://example.com/": _result(final_url="http://example.com/"),
        },
    )

    result = HttpDiscoveryProvider().discover("example.com")

    https_obs = next(o for o in result.http_observations if o.scheme == "https")
    assert https_obs.cookie_security_flags == [
        {"secure": True, "httponly": True, "samesite": "Strict"},
        {"secure": False, "httponly": False, "samesite": "Lax"},
    ]
    # The raw cookie strings (which carried the secret token/session
    # values) must never appear anywhere in the recorded observation.
    serialized = str(https_obs.cookie_security_flags)
    assert "super-secret-token-value" not in serialized
    assert "abc123" not in serialized


def test_status_codes_recorded_without_special_casing(monkeypatch):
    for status in (301, 302, 403, 404, 500):
        _patch_fetch(
            monkeypatch,
            {
                "https://example.com/": _result(status_code=status),
                "http://example.com/": _result(final_url="http://example.com/"),
            },
        )
        result = HttpDiscoveryProvider().discover("example.com")
        https_obs = next(o for o in result.http_observations if o.scheme == "https")
        assert https_obs.status_code == status
        assert https_obs.succeeded is True  # a 4xx/5xx is an observation, not a provider failure


def test_truncated_response_still_processed(monkeypatch):
    html = "<html><head><title>Truncated Page</title></head>" + ("x" * 10)
    _patch_fetch(
        monkeypatch,
        {
            "https://example.com/": _result(headers={"content-type": "text/html"}, text=html, truncated=True),
            "http://example.com/": _result(final_url="http://example.com/"),
        },
    )

    result = HttpDiscoveryProvider().discover("example.com")

    https_obs = next(o for o in result.http_observations if o.scheme == "https")
    assert https_obs.title == "Truncated Page"


def test_unexpected_exception_in_one_scheme_does_not_abort_the_other(monkeypatch):
    """Defense in depth: even a bug in classification logic (not just
    fetch_url itself) for one scheme must not crash discover() or take
    out the other scheme's result.
    """

    def _raise(url, _transport=None):
        raise RuntimeError("simulated unexpected failure")

    def _ok(url, _transport=None):
        return _result(final_url=url, status_code=200)

    def _fake(url, _transport=None):
        if url.startswith("https://"):
            return _raise(url)
        return _ok(url)

    monkeypatch.setattr(http_provider_module.http_client, "fetch_url", _fake)

    result = HttpDiscoveryProvider().discover("example.com")

    assert result.error is None
    by_scheme = {obs.scheme: obs for obs in result.http_observations}
    assert by_scheme["https"].succeeded is False
    assert "simulated unexpected failure" in by_scheme["https"].failure_reason
    assert by_scheme["http"].succeeded is True
