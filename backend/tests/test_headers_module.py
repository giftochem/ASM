from app.core.enums import FindingSeverity
from app.scanners.headers_module import HeadersModule
from app.scanners.http_client import FetchError, FetchResult


def _fake_fetch(monkeypatch, result):
    monkeypatch.setattr("app.scanners.headers_module.fetch", lambda target, *, scope: result)


_GOOD_HEADERS = {
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "content-security-policy": "default-src 'self'",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    "permissions-policy": "geolocation=()",
}


def test_all_headers_present_produces_only_info_finding(monkeypatch):
    result = FetchResult(
        final_url="https://example.com/", status_code=200, headers=_GOOD_HEADERS, text="", truncated=False
    )
    _fake_fetch(monkeypatch, result)

    module_result = HeadersModule().run("example.com")
    assert all(f.severity == FindingSeverity.info for f in module_result.findings)
    assert len(module_result.findings) == 1  # just the "analysis completed" summary


def test_all_headers_missing_never_produces_critical_or_high(monkeypatch):
    result = FetchResult(
        final_url="https://example.com/", status_code=200, headers={}, text="", truncated=False
    )
    _fake_fetch(monkeypatch, result)

    module_result = HeadersModule().run("example.com")
    severities = {f.severity for f in module_result.findings}
    assert FindingSeverity.critical not in severities
    assert FindingSeverity.high not in severities
    # Every header should have produced a finding except the summary
    assert len(module_result.findings) == 7  # 6 missing-header findings + 1 summary


def test_missing_headers_over_plain_http_skips_hsts(monkeypatch):
    result = FetchResult(
        final_url="http://example.com/", status_code=200, headers={}, text="", truncated=False
    )
    _fake_fetch(monkeypatch, result)

    module_result = HeadersModule().run("example.com")
    titles = [f.title for f in module_result.findings]
    assert not any("HSTS" in t or "Strict-Transport-Security" in t for t in titles)


def test_hsts_max_age_zero_is_flagged(monkeypatch):
    headers = dict(_GOOD_HEADERS, **{"strict-transport-security": "max-age=0"})
    result = FetchResult(
        final_url="https://example.com/", status_code=200, headers=headers, text="", truncated=False
    )
    _fake_fetch(monkeypatch, result)

    module_result = HeadersModule().run("example.com")
    titles = [f.title for f in module_result.findings]
    assert "HSTS explicitly disabled (max-age=0)" in titles
    finding = next(f for f in module_result.findings if f.title == "HSTS explicitly disabled (max-age=0)")
    assert finding.severity == FindingSeverity.medium


def test_short_hsts_max_age_is_low_severity(monkeypatch):
    headers = dict(_GOOD_HEADERS, **{"strict-transport-security": "max-age=60"})
    result = FetchResult(
        final_url="https://example.com/", status_code=200, headers=headers, text="", truncated=False
    )
    _fake_fetch(monkeypatch, result)

    module_result = HeadersModule().run("example.com")
    finding = next(f for f in module_result.findings if "shorter than recommended" in f.title)
    assert finding.severity == FindingSeverity.low


def test_weak_csp_directive_flagged_medium(monkeypatch):
    headers = dict(_GOOD_HEADERS, **{"content-security-policy": "default-src 'self' 'unsafe-inline'"})
    result = FetchResult(
        final_url="https://example.com/", status_code=200, headers=headers, text="", truncated=False
    )
    _fake_fetch(monkeypatch, result)

    module_result = HeadersModule().run("example.com")
    finding = next(f for f in module_result.findings if "weak directives" in f.title)
    assert finding.severity == FindingSeverity.medium


def test_malformed_x_frame_options_flagged_low(monkeypatch):
    headers = dict(_GOOD_HEADERS, **{"x-frame-options": "MAYBE"})
    result = FetchResult(
        final_url="https://example.com/", status_code=200, headers=headers, text="", truncated=False
    )
    _fake_fetch(monkeypatch, result)

    module_result = HeadersModule().run("example.com")
    finding = next(f for f in module_result.findings if "Unrecognized X-Frame-Options" in f.title)
    assert finding.severity == FindingSeverity.low


def test_csp_frame_ancestors_covers_missing_x_frame_options(monkeypatch):
    headers = dict(_GOOD_HEADERS)
    headers["content-security-policy"] = "frame-ancestors 'self'"
    del headers["x-frame-options"]
    result = FetchResult(
        final_url="https://example.com/", status_code=200, headers=headers, text="", truncated=False
    )
    _fake_fetch(monkeypatch, result)

    module_result = HeadersModule().run("example.com")
    titles = [f.title for f in module_result.findings]
    assert "Missing X-Frame-Options header" not in titles


def test_fetch_error_is_reported_as_module_error(monkeypatch):
    monkeypatch.setattr(
        "app.scanners.headers_module.fetch", lambda target, *, scope: FetchError("blocked target")
    )
    module_result = HeadersModule().run("example.com")
    assert module_result.error is not None
    assert module_result.findings == []
