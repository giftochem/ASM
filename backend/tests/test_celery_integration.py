"""Real FastAPI -> Redis -> Celery worker -> PostgreSQL integration test.

Deliberately does NOT use the FastAPI TestClient or the test database —
it makes real HTTP calls against the persistent `app` service, which
shares its (dev) database with the persistent `worker` service. That's
required for this to be a genuine test of the real pipeline: a separate
worker process can't see rows created through the TestClient's
test-database-scoped session, so this is the one place in the suite that
intentionally talks to the "real" stack instead of the isolated test one.

Requires `docker compose up -d db redis app worker` to be running first.
Skips (does not fail) if that stack isn't reachable — UNLESS
REQUIRE_CELERY_INTEGRATION=1 is set, in which case an unreachable stack
is a hard failure rather than a silent skip. Use that in CI/whenever you
want an infra outage to be caught, not hidden.
"""

import os
import time
import uuid

import httpx
import pytest

_BASE_URL = os.environ.get("ASM_INTEGRATION_BASE_URL", "http://app:8000")
_REQUIRE_INTEGRATION = os.environ.get("REQUIRE_CELERY_INTEGRATION", "").lower() in ("1", "true", "yes")
_POLL_TIMEOUT_SECONDS = 30
_POLL_INTERVAL_SECONDS = 1.0


def _check_stack_reachable() -> None:
    try:
        resp = httpx.get(f"{_BASE_URL}/health", timeout=3.0)
        resp.raise_for_status()
    except (httpx.HTTPError, httpx.TimeoutException) as exc:
        message = (
            f"Could not reach live app stack at {_BASE_URL} ({exc}). "
            "Run `docker compose up -d db redis app worker` first."
        )
        if _REQUIRE_INTEGRATION:
            pytest.fail(message)
        pytest.skip(message)


@pytest.fixture
def live_client():
    _check_stack_reachable()
    with httpx.Client(base_url=_BASE_URL, timeout=10.0) as c:
        yield c


def test_full_async_scan_pipeline_via_real_worker(live_client):
    token = uuid.uuid4().hex[:10]
    email = f"itest-{token}@example.com"

    register_resp = live_client.post(
        "/auth/register",
        json={
            "organization_name": f"Integration Test Org {token}",
            "email": email,
            "password": "correct-horse-battery",
            "full_name": "Integration Test",
        },
    )
    assert register_resp.status_code == 201, register_resp.text
    # Cookie-based auth: live_client (a real httpx.Client) keeps its own
    # cookie jar and resends Set-Cookie values automatically on
    # subsequent requests, same as a browser. Only the CSRF header needs
    # to be supplied explicitly on state-changing calls.
    csrf_token = live_client.cookies.get("csrf_token")
    assert csrf_token, "expected csrf_token cookie to be set after register"
    headers = {"X-CSRF-Token": csrf_token}

    asset_resp = live_client.post(
        "/assets",
        # domain, not subdomain: the "whois" module below only supports
        # asset_type=domain.
        json={"asset_type": "domain", "value": f"itest-{token}.com"},
        headers=headers,
    )
    assert asset_resp.status_code == 201, asset_resp.text
    asset = asset_resp.json()

    confirm_resp = live_client.post(
        f"/assets/{asset['id']}/confirm-authorization",
        json={"authorization_confirmed": True},
        headers=headers,
    )
    assert confirm_resp.status_code == 200

    # "dns" rather than "whois": a synthetic never-registered test domain
    # has no WHOIS record at all (the registry errors), which whois_module
    # correctly reports as a module error — a real WHOIS server also
    # rate-limits automated repeat queries, which a test suite run
    # repeatedly would trip. DNS module handles NXDOMAIN gracefully
    # (empty records + an info finding, not an error), so this proves the
    # real pipeline runs end-to-end without depending on real-world
    # registration state.
    scan_resp = live_client.post(
        "/scans", json={"asset_id": asset["id"], "modules": ["dns"]}, headers=headers
    )
    assert scan_resp.status_code == 201, scan_resp.text
    scan = scan_resp.json()
    # Under a real broker/worker this genuinely hasn't finished yet — that
    # IS the thing this test is meant to prove is really async.
    assert scan["status"] in ("queued", "running", "completed", "failed")

    deadline = time.monotonic() + _POLL_TIMEOUT_SECONDS
    final_scan = scan
    while time.monotonic() < deadline:
        poll_resp = live_client.get(f"/scans/{scan['id']}", headers=headers)
        assert poll_resp.status_code == 200
        final_scan = poll_resp.json()
        if final_scan["status"] not in ("queued", "running"):
            break
        time.sleep(_POLL_INTERVAL_SECONDS)

    assert final_scan["status"] == "completed", (
        f"scan did not complete via the real worker within {_POLL_TIMEOUT_SECONDS}s: {final_scan}"
    )
    assert len(final_scan["findings"]) > 0
