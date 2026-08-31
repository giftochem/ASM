"""Cookie-auth security properties not already covered by test_auth.py's
happy-path flow: CSRF enforcement, refresh-token rotation/reuse
detection, and revocation propagation.
"""

import re
import threading

from app.services import refresh_token_service
from tests.conftest import TestSessionLocal


def _split_cookie_and_csrf(headers: dict) -> tuple[str, str]:
    """register_user()/login_as() return a headers dict with a combined
    Cookie header plus X-CSRF-Token — a few tests here need to mutate one
    without the other, so pull them apart.
    """
    cookie = headers["Cookie"]
    csrf = headers["X-CSRF-Token"]
    return cookie, csrf


def test_csrf_missing_header_rejected(client, register_user):
    headers = register_user()
    cookie, _ = _split_cookie_and_csrf(headers)

    resp = client.post("/assets", json={"asset_type": "domain", "value": "example.com"}, headers={"Cookie": cookie})
    assert resp.status_code == 403
    assert "csrf" in resp.json()["detail"].lower()


def test_csrf_mismatched_header_rejected(client, register_user):
    headers = register_user()
    cookie, _ = _split_cookie_and_csrf(headers)

    resp = client.post(
        "/assets",
        json={"asset_type": "domain", "value": "example.com"},
        headers={"Cookie": cookie, "X-CSRF-Token": "not-the-real-token"},
    )
    assert resp.status_code == 403


def test_csrf_not_required_for_get_requests(client, register_user):
    headers = register_user()
    cookie, _ = _split_cookie_and_csrf(headers)

    resp = client.get("/assets", headers={"Cookie": cookie})
    assert resp.status_code == 200


def test_csrf_valid_header_is_accepted(client, register_user):
    headers = register_user()
    resp = client.post("/assets", json={"asset_type": "domain", "value": "example.com"}, headers=headers)
    assert resp.status_code == 201


def test_register_and_login_are_csrf_exempt(client):
    # No X-CSRF-Token at all -- must still succeed, since there's no
    # session cookie yet for a forged cross-site request to ride.
    resp = client.post(
        "/auth/register",
        json={
            "organization_name": "CSRF Exempt Org",
            "email": "csrf-exempt@example.com",
            "password": "correct-horse-battery",
            "full_name": "No CSRF Needed",
        },
    )
    assert resp.status_code == 201


def test_refresh_token_rotation_old_token_is_single_use(client, register_user):
    # register_user() clears the client's jar before returning (so a
    # second call in the same test starts clean) -- the old refresh/csrf
    # values must be captured from its returned headers, not client.cookies.
    headers = register_user(email="rotate@example.com")
    old_cookie, old_csrf = _split_cookie_and_csrf(headers)
    old_refresh = re.search(r"refresh_token=([^;]+)", old_cookie).group(1)

    first_refresh = client.post("/auth/refresh", headers=headers)
    assert first_refresh.status_code == 200
    new_refresh = client.cookies.get("refresh_token")
    assert new_refresh != old_refresh

    # Replaying the now-rotated-away token must fail. Include a valid
    # matching CSRF pair so this actually exercises refresh-token
    # validation rather than being rejected by CSRF first.
    replay_resp = client.post(
        "/auth/refresh",
        headers={"Cookie": f"refresh_token={old_refresh}; csrf_token={old_csrf}", "X-CSRF-Token": old_csrf},
    )
    assert replay_resp.status_code == 401


def test_refresh_token_reuse_revokes_all_sessions(client, register_user):
    """Presenting an already-rotated (revoked) refresh token is treated as
    a compromise signal: every other active refresh token for that user
    gets revoked too, not just the reused one.
    """
    headers = register_user(email="reuse@example.com")
    old_cookie, csrf = _split_cookie_and_csrf(headers)
    original_refresh = re.search(r"refresh_token=([^;]+)", old_cookie).group(1)

    # Legitimate rotation.
    first = client.post("/auth/refresh", headers=headers)
    assert first.status_code == 200
    latest_refresh = client.cookies.get("refresh_token")
    assert latest_refresh != original_refresh

    # Replay the ORIGINAL (now-revoked) token -- reuse detected.
    reuse_resp = client.post(
        "/auth/refresh",
        headers={
            "Cookie": f"refresh_token={original_refresh}; csrf_token={csrf}",
            "X-CSRF-Token": csrf,
        },
    )
    assert reuse_resp.status_code == 401

    # The legitimately-rotated latest token must ALSO now be dead --
    # reuse detection revokes the whole chain, not just the replayed token.
    latest_after_reuse = client.post(
        "/auth/refresh",
        headers={
            "Cookie": f"refresh_token={latest_refresh}; csrf_token={csrf}",
            "X-CSRF-Token": csrf,
        },
    )
    assert latest_after_reuse.status_code == 401


def test_refresh_with_garbage_token_rejected(client):
    # A valid, matching CSRF pair is required so this actually reaches
    # refresh-token validation instead of being rejected by CSRF first
    # (CSRF is checked in middleware, ahead of any route logic, by design).
    resp = client.post(
        "/auth/refresh",
        headers={
            "Cookie": "refresh_token=not-a-real-jwt-at-all; csrf_token=x",
            "X-CSRF-Token": "x",
        },
    )
    assert resp.status_code == 401


def test_refresh_without_refresh_cookie_rejected(client):
    # Valid CSRF pair present, but no refresh_token cookie at all --
    # isolates "no refresh token" (401) from "no/invalid CSRF" (403).
    resp = client.post(
        "/auth/refresh", headers={"Cookie": "csrf_token=x", "X-CSRF-Token": "x"}
    )
    assert resp.status_code == 401


def test_refresh_with_no_cookies_or_csrf_at_all_is_rejected_by_csrf_first(client):
    """CSRF is enforced in middleware, ahead of any route-specific logic
    — a completely bare request never even reaches the "is there a
    refresh token" check. Both are "you're not authenticated", but this
    pins down which layer actually catches it.
    """
    resp = client.post("/auth/refresh")
    assert resp.status_code == 403


def test_access_token_cookie_alone_without_csrf_cannot_write(client, register_user):
    """Simulates the concrete threat model double-submit defends against:
    an attacker who can make the victim's browser send a request (riding
    ambient cookies) but can't read the csrf_token cookie's value
    cross-origin, so can't produce a matching header.
    """
    headers = register_user()
    cookie, _ = _split_cookie_and_csrf(headers)
    access_only_cookie = re.sub(r";?\s*csrf_token=[^;]+", "", cookie)

    resp = client.post(
        "/assets", json={"asset_type": "domain", "value": "example.com"}, headers={"Cookie": access_only_cookie}
    )
    assert resp.status_code == 403


def test_concurrent_refresh_with_same_token_exactly_one_succeeds(client, register_user):
    """Regression for the refresh-rotation TOCTOU race (Step 7A
    remediation, finding M-1). The old code read `row.revoked_at`, then
    separately wrote it — two threads presenting the same still-valid
    refresh token could both pass the read check before either committed,
    both minting new tokens from one presented token. Drives
    refresh_token_service.rotate() from two real threads with two
    separate DB sessions (mirroring test_scan_race_safety.py's pattern
    for the identical class of bug in scan status transitions) and
    asserts the atomic conditional UPDATE lets exactly one caller win.
    """
    headers = register_user(email="concurrent-refresh@example.com")
    cookie, _ = _split_cookie_and_csrf(headers)
    refresh_token = re.search(r"refresh_token=([^;]+)", cookie).group(1)

    barrier = threading.Barrier(2)
    results = {}
    lock = threading.Lock()

    def _do_rotate(name: str) -> None:
        session = TestSessionLocal()
        try:
            barrier.wait(timeout=5)
            try:
                refresh_token_service.rotate(session, refresh_token)
                outcome = "succeeded"
            except refresh_token_service.RefreshTokenError as exc:
                outcome = f"failed:{exc.reason}"
            with lock:
                results[name] = outcome
        finally:
            session.close()

    t1 = threading.Thread(target=_do_rotate, args=("t1",))
    t2 = threading.Thread(target=_do_rotate, args=("t2",))
    t1.start()
    t2.start()
    t1.join(timeout=10)
    t2.join(timeout=10)

    assert set(results) == {"t1", "t2"}
    outcomes = sorted(results.values())
    # Exactly one winner, one loser -- never both succeeding (which would
    # mean the single-use guarantee broke under the race) and never both
    # failing (which would mean a legitimate concurrent refresh, e.g. two
    # browser tabs, was needlessly rejected).
    assert outcomes.count("succeeded") == 1
    assert len([o for o in outcomes if o != "succeeded"]) == 1
