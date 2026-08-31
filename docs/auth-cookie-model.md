# Cookie-Based Authentication Model

Implemented in `backend/app/security.py`, `backend/app/core/cookies.py`,
`backend/app/core/csrf_middleware.py`, `backend/app/services/
refresh_token_service.py`, and `backend/app/api/routes/auth.py`. This
document and that code must stay in sync — if you change one, change the
other, and update `backend/tests/test_auth.py` /
`backend/tests/test_auth_cookies.py` to match.

## Why cookies instead of the Phase 1/2 bearer-token model

Phase 1/2 returned `access_token`/`refresh_token` as JSON in the
response body, for the caller to store and send back as
`Authorization: Bearer <token>`. That's fine for a pure API client, but
wrong for a browser-based frontend (Phase 3b): any token a page's own
JavaScript can read, an XSS bug on that page can also read and exfiltrate.
Phase 3a keeps the underlying JWT model — same claims, same signing,
same short-lived-access/longer-lived-refresh split — and changes only the
**transport**: tokens now travel exclusively as `httpOnly` cookies,
invisible to JavaScript entirely, set once at login/register/refresh and
never echoed back in a response body.

## The three cookies

| Cookie | httpOnly | Path | Lifetime | Purpose |
|---|---|---|---|---|
| `access_token` | yes | `/` | 15 min (`ACCESS_TOKEN_EXPIRE_MINUTES`) | Short-lived JWT, read by `get_current_user` on every request |
| `refresh_token` | yes | `/auth` | 7 days (`REFRESH_TOKEN_EXPIRE_DAYS`) | Long-lived JWT with a `jti`, used only by `/auth/refresh` and `/auth/logout` |
| `csrf_token` | **no** | `/` | matches refresh lifetime | Opaque random value, deliberately readable by same-origin JS — see CSRF below |

All three: `Secure` in production only (`ENVIRONMENT=production` →
`Settings.cookie_secure`; off in dev/test so cookies still work over
plain `http://localhost`), `SameSite=Strict` (see below for why this is
safe here), set/cleared exclusively through
`app.core.cookies.set_auth_cookies()` / `clear_auth_cookies()` — no route
handler ever calls `response.set_cookie` directly, so the flags can't
drift out of sync between endpoints.

`refresh_token` is scoped to `Path=/auth` specifically so it's never sent
on ordinary API calls (`/assets`, `/scans`, ...) — only the two endpoints
that actually need it ever see it on the wire, shrinking its exposure
window.

**Why `SameSite=Strict` is sufficient here, with no cross-origin
carve-out:** the frontend (Phase 3b) is always served same-site with the
API — via nginx reverse-proxying both, in production, and via the Vite
dev server's own proxy in local dev — so cookies never need to cross an
origin boundary at all. `Strict` is the most restrictive setting
available and there's no legitimate flow this codebase needs that it
would break.

## CSRF protection: double-submit cookie

`SameSite=Strict` alone already blocks a cross-site page's `fetch`/XHR
requests from carrying these cookies in most browsers, but this codebase
adds an explicit, verifiable second layer rather than relying solely on
a browser-behavior guarantee: **double-submit cookie**.

1. `csrf_token` is set as a *non*-httpOnly cookie alongside the two
   session cookies — same-origin JavaScript can read it via
   `document.cookie`.
2. The frontend must echo that value back in an `X-CSRF-Token` header on
   every state-changing request.
3. `app.core.csrf_middleware.CSRFMiddleware`, applied globally (not as a
   per-route dependency — so a new POST/PUT/PATCH/DELETE route can't ship
   without this check just because someone forgot to add a dependency),
   rejects any `POST`/`PUT`/`PATCH`/`DELETE` request where the header is
   missing or doesn't match the cookie (constant-time comparison via
   `hmac.compare_digest`), with `403`.

**Why this defeats CSRF:** a malicious cross-site page can make the
victim's browser *send* a request that carries the victim's cookies (if
`SameSite` were ever weakened, or in a browser with unusual cookie
handling), but it **cannot read** the `csrf_token` cookie's value —
same-origin policy blocks that regardless of `SameSite`. Without the
value, it cannot produce a matching `X-CSRF-Token` header, so the request
is rejected even though the cookies rode along.

**Exempt paths:** `POST /auth/register` and `POST /auth/login` skip this
check (`app.core.cookies.CSRF_EXEMPT_PATHS`). Both are
*credential*-authenticated (email + password in the request body), not
*cookie*-authenticated — there's no ambient session credential yet for a
forged cross-site request to ride, so classic CSRF doesn't apply to them.
`/auth/refresh` and `/auth/logout` **are** protected, since both rely on
the ambient `refresh_token` cookie.

## Refresh-token rotation and revocation

A JWT's signature proves authenticity but says nothing about whether that
*specific* token should still be honored — there's no way to revoke one
without server-side state. `app.models.refresh_token.RefreshToken` is
that state: one row per issued refresh token, keyed by the `jti` claim
embedded in the JWT itself.

- **Issue** (`refresh_token_service.issue`): creates a `RefreshToken` row
  and a JWT carrying its id as `jti`.
- **Rotate** (`refresh_token_service.rotate`, called by `POST
  /auth/refresh`): validates the presented token, marks its row
  `revoked_at = now()`, and issues a brand new one. Every refresh token
  is **single-use** — the one just presented can never be presented
  again successfully.
- **Reuse detection**: if a presented token's row is *already* revoked,
  that's a signal something is wrong — a legitimate client never
  re-presents a token it already rotated away from. Every other active
  refresh token for that user is revoked immediately
  (`revoke_all_for_user`), forcing a full re-login everywhere. This is
  what limits the blast radius of a stolen-and-replayed refresh token,
  rather than only invalidating the one copy that got caught.
- **Revoke** (`refresh_token_service.revoke`, called by `POST
  /auth/logout`): revokes the current refresh token's row and clears all
  three cookies. Logout is real, server-side revocation, not just "the
  browser forgets the cookie" — a copy of the token an attacker made
  before logout stops working immediately, not merely at its natural
  7-day expiry.

Access tokens are **not** individually tracked or revocable — they stay
fully stateless (no DB lookup on every authenticated request) and rely
entirely on their 15-minute lifetime to bound exposure after a logout or
compromise. This is a deliberate trade-off: checking revocation state on
every single API call would add a DB round-trip to the hot path for a
token type that's already short-lived by design.

## Threat model summary

| Threat | Mitigation |
|---|---|
| XSS reading/exfiltrating tokens | `httpOnly` on `access_token`/`refresh_token` — never readable by any JS, malicious or not |
| CSRF (cross-site request riding cookies) | `SameSite=Strict` + double-submit `csrf_token` header check |
| Stolen refresh token replayed after legitimate use | Single-use rotation — a replayed token is instantly detected (already revoked) |
| Stolen refresh token used before the legitimate client refreshes | Reuse detection revokes every other active token for that user once the legitimate client *does* refresh and the theft is discovered |
| Token still valid after logout | Real server-side revocation via `RefreshToken.revoked_at`, not just cookie deletion |
| Long-lived token exposure window | Access tokens expire in 15 minutes regardless of any of the above |

## What's explicitly out of scope for Phase 3a

- No "log out of all other sessions" user-facing endpoint yet (the
  underlying `revoke_all_for_user` exists and is exercised by reuse
  detection, just not exposed as a deliberate user action).
- No device/session listing UI (Phase 3b, if wanted).
