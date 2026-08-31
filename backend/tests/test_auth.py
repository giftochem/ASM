def test_register_creates_org_and_admin_via_cookies_not_body(client):
    resp = client.post(
        "/auth/register",
        json={
            "organization_name": "Acme Corp",
            "email": "admin@example.com",
            "password": "correct-horse-battery",
            "full_name": "Ada Admin",
        },
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["email"] == "admin@example.com"
    # Tokens must never appear in the response body — cookies only.
    assert "access_token" not in body
    assert "refresh_token" not in body
    assert client.cookies.get("access_token") is not None
    assert client.cookies.get("refresh_token") is not None
    assert client.cookies.get("csrf_token") is not None


def test_register_duplicate_email_rejected(client):
    payload = {
        "organization_name": "Acme Corp",
        "email": "dupe@example.com",
        "password": "correct-horse-battery",
        "full_name": "Ada Admin",
    }
    first = client.post("/auth/register", json=payload)
    assert first.status_code == 201

    second = client.post(
        "/auth/register", json={**payload, "organization_name": "Other Org"}
    )
    assert second.status_code == 409


def test_login_with_wrong_password_rejected(client):
    client.post(
        "/auth/register",
        json={
            "organization_name": "Acme Corp",
            "email": "user@example.com",
            "password": "correct-horse-battery",
            "full_name": "Regular User",
        },
    )
    client.cookies.clear()
    resp = client.post(
        "/auth/login", data={"username": "user@example.com", "password": "wrong-password"}
    )
    assert resp.status_code == 401
    assert client.cookies.get("access_token") is None


def test_login_and_refresh_flow(client):
    client.post(
        "/auth/register",
        json={
            "organization_name": "Acme Corp",
            "email": "flow@example.com",
            "password": "correct-horse-battery",
            "full_name": "Flow User",
        },
    )
    old_refresh_token = client.cookies.get("refresh_token")
    client.cookies.clear()

    login_resp = client.post(
        "/auth/login", data={"username": "flow@example.com", "password": "correct-horse-battery"}
    )
    assert login_resp.status_code == 200

    me_resp = client.get("/users/me")
    assert me_resp.status_code == 200
    assert me_resp.json()["email"] == "flow@example.com"

    old_csrf = client.cookies.get("csrf_token")
    refresh_resp = client.post("/auth/refresh", headers={"X-CSRF-Token": old_csrf})
    assert refresh_resp.status_code == 200
    new_access_token = client.cookies.get("access_token")
    new_refresh_token = client.cookies.get("refresh_token")
    assert new_access_token is not None
    assert new_refresh_token is not None
    assert new_refresh_token != old_refresh_token  # rotated, not reused

    # New access token actually works.
    me_resp_2 = client.get("/users/me")
    assert me_resp_2.status_code == 200


def test_unauthenticated_request_rejected(client):
    resp = client.get("/users/me")
    assert resp.status_code == 401


def test_logout_clears_cookies_and_revokes_refresh_token(client):
    client.post(
        "/auth/register",
        json={
            "organization_name": "Acme Corp",
            "email": "logout@example.com",
            "password": "correct-horse-battery",
            "full_name": "Logout User",
        },
    )
    csrf = client.cookies.get("csrf_token")
    refresh_token_before = client.cookies.get("refresh_token")

    logout_resp = client.post("/auth/logout", headers={"X-CSRF-Token": csrf})
    assert logout_resp.status_code == 204
    assert client.cookies.get("access_token") is None
    assert client.cookies.get("refresh_token") is None
    assert client.cookies.get("csrf_token") is None

    # The now-revoked refresh token must not work even if replayed
    # manually (simulating a copy an attacker made before logout). Include
    # a valid matching CSRF pair -- logout cleared it from the jar, so it
    # has to be supplied explicitly to reach refresh-token validation at
    # all (CSRF is checked first, in middleware).
    resp = client.post(
        "/auth/refresh",
        headers={
            "Cookie": f"refresh_token={refresh_token_before}; csrf_token={csrf}",
            "X-CSRF-Token": csrf,
        },
    )
    assert resp.status_code == 401


def test_cookies_carry_expected_security_flags(client):
    resp = client.post(
        "/auth/register",
        json={
            "organization_name": "Acme Corp",
            "email": "flags@example.com",
            "password": "correct-horse-battery",
            "full_name": "Flags User",
        },
    )
    set_cookie_headers = resp.headers.get_list("set-cookie")
    by_name = {}
    for raw in set_cookie_headers:
        name = raw.split("=", 1)[0]
        by_name[name] = raw.lower()

    assert "access_token" in by_name
    assert "httponly" in by_name["access_token"]
    assert "samesite=strict" in by_name["access_token"]

    assert "refresh_token" in by_name
    assert "httponly" in by_name["refresh_token"]
    assert "samesite=strict" in by_name["refresh_token"]
    assert "path=/auth" in by_name["refresh_token"]

    # csrf_token must be readable by frontend JS -- NOT httpOnly.
    assert "csrf_token" in by_name
    assert "httponly" not in by_name["csrf_token"]
    assert "samesite=strict" in by_name["csrf_token"]

    # Test/dev environment: Secure is off so cookies work over plain
    # http:// during local development; production sets ENVIRONMENT=
    # production, which flips this on (see app.config.Settings.cookie_secure).
    assert "secure" not in by_name["access_token"]


def test_login_invokes_password_verification_for_both_wrong_password_and_nonexistent_user(
    client, register_user, monkeypatch
):
    """Regression for the login-timing user-enumeration side-channel
    (Step 7A remediation, finding H-1). Before the fix, `user is None or
    not verify_password(...)` short-circuited verify_password entirely
    for a nonexistent email, creating a measurable timing gap between
    "no such account" and "wrong password" despite both returning the
    same response. Proven here via a call-count spy rather than a timing
    measurement (which would be flaky in CI) — this directly proves the
    code path that equalizes the cost actually runs on both branches.
    """
    import app.api.routes.auth as auth_module
    from app.security import DUMMY_PASSWORD_HASH

    register_user(email="h1-verify@example.com")
    client.cookies.clear()

    calls = []
    real_verify_password = auth_module.verify_password

    def spy(plain_password, password_hash):
        calls.append((plain_password, password_hash))
        return real_verify_password(plain_password, password_hash)

    monkeypatch.setattr(auth_module, "verify_password", spy)

    # Wrong password for a REAL, existing user.
    resp1 = client.post(
        "/auth/login", data={"username": "h1-verify@example.com", "password": "wrong-password"}
    )
    assert resp1.status_code == 401
    assert resp1.json()["detail"] == "Incorrect email or password"

    # A completely nonexistent user.
    resp2 = client.post(
        "/auth/login", data={"username": "no-such-user-h1@example.com", "password": "irrelevant"}
    )
    assert resp2.status_code == 401
    assert resp2.json()["detail"] == "Incorrect email or password"

    # Both paths must invoke verify_password exactly once each — proving
    # the nonexistent-user path is NOT short-circuited.
    assert len(calls) == 2
    # And the nonexistent-user call ran against the dummy hash, not a
    # skipped/None comparison.
    assert calls[1][1] == DUMMY_PASSWORD_HASH
    # The real user's call ran against their actual stored hash.
    assert calls[0][1] != DUMMY_PASSWORD_HASH
