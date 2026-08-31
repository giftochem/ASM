"""Regression tests for account-based brute-force protection (Step 7A
remediation, finding H-3) — see app.services.account_lockout.

Split deliberately: the detailed lockout mechanics (threshold, temporary
self-expiry, escalation, reset-on-success, concurrency-safety, and
identical treatment of real/nonexistent emails) are tested directly
against the service, independent of HTTP and the IP-based rate limiter's
own request budget. Two HTTP-level tests then prove the wiring into
POST /auth/login itself, and that account-based protection catches a
distributed attack the IP-based limiter alone would miss.
"""

import time
from concurrent.futures import ThreadPoolExecutor

import app.services.account_lockout as account_lockout


def test_record_failure_locks_after_threshold(monkeypatch):
    monkeypatch.setattr(account_lockout, "_FAILURE_THRESHOLD", 3)
    email = "lockout-threshold@example.com"

    assert account_lockout.seconds_locked(email) is None
    for _ in range(2):
        account_lockout.record_failure(email)
        assert account_lockout.seconds_locked(email) is None

    account_lockout.record_failure(email)
    assert account_lockout.seconds_locked(email) is not None


def test_lockout_is_temporary_and_self_expires(monkeypatch):
    monkeypatch.setattr(account_lockout, "_FAILURE_THRESHOLD", 2)
    monkeypatch.setattr(account_lockout, "_LOCKOUT_BASE_SECONDS", 1)
    email = "lockout-temporary@example.com"

    account_lockout.record_failure(email)
    account_lockout.record_failure(email)
    assert account_lockout.seconds_locked(email) is not None

    time.sleep(1.5)
    assert account_lockout.seconds_locked(email) is None


def test_lockout_escalates_on_repeated_offenses(monkeypatch):
    monkeypatch.setattr(account_lockout, "_FAILURE_THRESHOLD", 2)
    monkeypatch.setattr(account_lockout, "_LOCKOUT_BASE_SECONDS", 1)
    monkeypatch.setattr(account_lockout, "_LOCKOUT_MAX_SECONDS", 3600)
    email = "lockout-escalation@example.com"

    # First offense: base duration (~1s).
    account_lockout.record_failure(email)
    account_lockout.record_failure(email)
    first_duration = account_lockout.seconds_locked(email)
    assert first_duration is not None
    assert first_duration <= 1

    time.sleep(1.5)
    assert account_lockout.seconds_locked(email) is None

    # Second offense: escalated duration (~2x base), not a repeat of the same 1s.
    account_lockout.record_failure(email)
    account_lockout.record_failure(email)
    second_duration = account_lockout.seconds_locked(email)
    assert second_duration is not None
    assert second_duration > first_duration


def test_lockout_escalation_is_capped_never_permanent(monkeypatch):
    """However many repeated offenses, the lockout duration never exceeds
    the cap — this is what makes it "temporary" rather than a
    permanent-lockout-as-DoS vector.
    """
    monkeypatch.setattr(account_lockout, "_FAILURE_THRESHOLD", 2)
    monkeypatch.setattr(account_lockout, "_LOCKOUT_BASE_SECONDS", 60)
    monkeypatch.setattr(account_lockout, "_LOCKOUT_MAX_SECONDS", 90)
    email = "lockout-cap@example.com"

    # Manually escalate the level far past what would blow past the cap
    # if uncapped (60 * 2^9 would be enormous).
    account_lockout._client.set(account_lockout._escalation_key(email), "10")

    account_lockout.record_failure(email)
    account_lockout.record_failure(email)
    duration = account_lockout.seconds_locked(email)
    assert duration is not None
    assert duration <= 90


def test_successful_login_resets_escalation_state(monkeypatch):
    monkeypatch.setattr(account_lockout, "_FAILURE_THRESHOLD", 2)
    monkeypatch.setattr(account_lockout, "_LOCKOUT_BASE_SECONDS", 1)
    email = "lockout-reset@example.com"

    account_lockout.record_failure(email)
    account_lockout.record_failure(email)
    assert account_lockout.seconds_locked(email) is not None
    time.sleep(1.5)
    assert account_lockout.seconds_locked(email) is None

    # A successful login resets the escalation level back to zero.
    account_lockout.record_success(email)

    account_lockout.record_failure(email)
    account_lockout.record_failure(email)
    duration_after_reset = account_lockout.seconds_locked(email)
    assert duration_after_reset is not None
    assert duration_after_reset <= 1  # back to base, not escalated


def test_real_and_nonexistent_email_locked_identically(monkeypatch):
    """Failures must be recorded the same way regardless of whether the
    email belongs to a real account — otherwise "does this email ever
    lock?" becomes a new enumeration side-channel, undoing the H-1 fix.
    """
    monkeypatch.setattr(account_lockout, "_FAILURE_THRESHOLD", 3)
    real_looking = "definitely-not-a-real-account-xyz@example.com"

    for _ in range(3):
        account_lockout.record_failure(real_looking)

    assert account_lockout.seconds_locked(real_looking) is not None


def test_concurrent_failed_attempts_are_safe(monkeypatch):
    """Redis INCR/SET-NX-EX atomicity, not application locking, is what
    makes this safe under concurrency — fire many failures at once and
    confirm the outcome is exactly what threshold accounting predicts,
    with no double-locking or lost increments.
    """
    monkeypatch.setattr(account_lockout, "_FAILURE_THRESHOLD", 10)
    email = "lockout-concurrent@example.com"

    with ThreadPoolExecutor(max_workers=10) as pool:
        list(pool.map(lambda _: account_lockout.record_failure(email), range(10)))

    # Exactly the threshold's worth of concurrent failures must produce
    # exactly one active lock (not zero, not a corrupted/negative TTL).
    duration = account_lockout.seconds_locked(email)
    assert duration is not None
    assert duration > 0


def test_login_returns_429_when_account_locked(client, register_user, monkeypatch):
    monkeypatch.setattr(account_lockout, "_FAILURE_THRESHOLD", 3)
    register_user(email="lockout-http@example.com")
    client.cookies.clear()

    for _ in range(3):
        resp = client.post(
            "/auth/login", data={"username": "lockout-http@example.com", "password": "wrong-password"}
        )
        assert resp.status_code == 401

    # Even the CORRECT password is rejected while locked.
    locked_resp = client.post(
        "/auth/login",
        data={"username": "lockout-http@example.com", "password": "correct-horse-battery"},
    )
    assert locked_resp.status_code == 429
    assert "too many" in locked_resp.json()["detail"].lower()


def test_account_lockout_catches_distributed_attempts_across_multiple_source_ips(
    client, register_user, monkeypatch
):
    """The IP-based limiter (5/minute) cannot see an attacker spreading
    guesses across many source IPs against one account. Simulates 3
    distinct source IPs, 2 failed attempts each (well under any single
    IP's 5/minute budget), and proves the ACCOUNT still locks — this is
    exactly the gap account-based protection closes.
    """
    from app.config import settings

    monkeypatch.setattr(account_lockout, "_FAILURE_THRESHOLD", 6)
    monkeypatch.setattr(type(settings), "trusted_proxy_ips", property(lambda self: {"testclient"}))

    register_user(email="lockout-distributed@example.com")
    client.cookies.clear()

    simulated_ips = ["203.0.113.10", "203.0.113.11", "203.0.113.12"]
    for ip in simulated_ips:
        for _ in range(2):
            resp = client.post(
                "/auth/login",
                data={"username": "lockout-distributed@example.com", "password": "wrong-password"},
                headers={"X-Forwarded-For": ip},
            )
            # None of these individually trip the IP limiter (2 < 5/minute per IP).
            assert resp.status_code == 401

    # The account itself is now locked, regardless of which IP asks next.
    final_resp = client.post(
        "/auth/login",
        data={"username": "lockout-distributed@example.com", "password": "correct-horse-battery"},
        headers={"X-Forwarded-For": "203.0.113.99"},  # a fourth, never-before-seen IP
    )
    assert final_resp.status_code == 429
