from app.scanners.http_client import FetchError, FetchResult
from app.scanners.technology_module import TechnologyModule


def _fake_fetch(monkeypatch, result):
    monkeypatch.setattr("app.scanners.technology_module.fetch", lambda target: result)


def test_detects_wordpress_via_header_and_body(monkeypatch):
    result = FetchResult(
        final_url="https://example.com/",
        status_code=200,
        headers={"set-cookie": "wordpress_logged_in=abc123; Path=/"},
        text='<meta name="generator" content="WordPress 6.4" /><div>wp-content/themes/x</div>',
        truncated=False,
    )
    _fake_fetch(monkeypatch, result)

    module_result = TechnologyModule().run("example.com")
    names = {t["name"] for t in module_result.raw_data["technologies"]}
    assert "WordPress" in names


def test_detects_nginx_via_server_header(monkeypatch):
    result = FetchResult(
        final_url="https://example.com/",
        status_code=200,
        headers={"server": "nginx/1.25.3"},
        text="<html></html>",
        truncated=False,
    )
    _fake_fetch(monkeypatch, result)

    module_result = TechnologyModule().run("example.com")
    names = {t["name"] for t in module_result.raw_data["technologies"]}
    assert "nginx" in names


def test_detects_react_via_body_signature(monkeypatch):
    result = FetchResult(
        final_url="https://example.com/",
        status_code=200,
        headers={},
        text='<div id="root" data-reactroot=""></div>',
        truncated=False,
    )
    _fake_fetch(monkeypatch, result)

    module_result = TechnologyModule().run("example.com")
    names = {t["name"] for t in module_result.raw_data["technologies"]}
    assert "React" in names


def test_no_signatures_detected(monkeypatch):
    result = FetchResult(
        final_url="https://example.com/",
        status_code=200,
        headers={},
        text="<html><body>plain page</body></html>",
        truncated=False,
    )
    _fake_fetch(monkeypatch, result)

    module_result = TechnologyModule().run("example.com")
    assert module_result.raw_data["technologies"] == []
    assert module_result.findings[0].title == "No known technology signatures detected"


def test_fetch_error_is_reported_as_module_error(monkeypatch):
    _fake_fetch(monkeypatch, FetchError("blocked target: private address"))
    module_result = TechnologyModule().run("example.com")
    assert module_result.error is not None
    assert module_result.findings == []


def test_detection_never_executes_fetched_content(monkeypatch):
    """Signature matching is plain regex/substring matching against text
    already fetched — nothing here should ever eval/exec/import the body.
    A body containing script-like content should just be inert text.
    """
    result = FetchResult(
        final_url="https://example.com/",
        status_code=200,
        headers={},
        text="<script>__import__('os').system('echo pwned')</script> wp-content/",
        truncated=False,
    )
    _fake_fetch(monkeypatch, result)

    module_result = TechnologyModule().run("example.com")
    # It's allowed to detect WordPress from "wp-content/" in that string —
    # the point is nothing executed and this returns normally with data,
    # not a side effect.
    assert isinstance(module_result.raw_data["technologies"], list)
