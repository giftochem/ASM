"""Shared cookie/header names — and the one place that actually sets/clears
them — for cookie-based auth, so app.dependencies, app.api.routes.auth,
and the CSRF middleware can't drift out of sync with each other. See
docs/auth-cookie-model.md for the full model.
"""

from fastapi import Response

from app.config import settings

ACCESS_TOKEN_COOKIE = "access_token"
REFRESH_TOKEN_COOKIE = "refresh_token"
CSRF_TOKEN_COOKIE = "csrf_token"
CSRF_HEADER_NAME = "X-CSRF-Token"

# refresh_token is scoped to /auth so it's never sent on ordinary API
# calls — only the endpoints that actually need it (refresh, logout) ever
# see it on the wire.
REFRESH_TOKEN_COOKIE_PATH = "/auth"
DEFAULT_COOKIE_PATH = "/"

# CSRF protection is skipped for these paths: both are credential-
# authenticated (email+password in the body), not cookie-authenticated,
# so classic CSRF (an attacker's page riding the victim's ambient cookie
# to perform an action) doesn't apply — there's no ambient credential to
# ride yet. Every other state-changing endpoint relies on the session
# cookies and is protected.
CSRF_EXEMPT_PATHS = {"/auth/register", "/auth/login"}


def set_auth_cookies(response: Response, access_token: str, refresh_token: str, csrf_token: str) -> None:
    """The only place in the codebase that should ever call
    response.set_cookie for these three — keeps the flags (httpOnly,
    Secure, SameSite) consistent everywhere they're issued.
    """
    response.set_cookie(
        ACCESS_TOKEN_COOKIE,
        access_token,
        max_age=settings.access_token_expire_minutes * 60,
        path=DEFAULT_COOKIE_PATH,
        httponly=True,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
    )
    response.set_cookie(
        REFRESH_TOKEN_COOKIE,
        refresh_token,
        max_age=settings.refresh_token_expire_days * 86400,
        path=REFRESH_TOKEN_COOKIE_PATH,
        httponly=True,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
    )
    response.set_cookie(
        CSRF_TOKEN_COOKIE,
        csrf_token,
        max_age=settings.refresh_token_expire_days * 86400,
        path=DEFAULT_COOKIE_PATH,
        # Deliberately NOT httponly — the frontend must be able to read
        # this value with JS to echo it back in the X-CSRF-Token header.
        # It is not a secret on its own; the double-submit pattern's
        # security comes from a cross-origin attacker being unable to
        # read it, not from it being hidden from same-origin JS.
        httponly=False,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
    )


def clear_auth_cookies(response: Response) -> None:
    response.delete_cookie(ACCESS_TOKEN_COOKIE, path=DEFAULT_COOKIE_PATH)
    response.delete_cookie(REFRESH_TOKEN_COOKIE, path=REFRESH_TOKEN_COOKIE_PATH)
    response.delete_cookie(CSRF_TOKEN_COOKIE, path=DEFAULT_COOKIE_PATH)
