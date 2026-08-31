"""Double-submit-cookie CSRF protection, applied globally as middleware
rather than a per-route dependency — so a new state-changing route can't
accidentally ship without it (req: RBAC/security checks must be enforced
server-side and can't be silently skipped by omission).

See docs/auth-cookie-model.md for the full model and why SameSite=strict
cookies alone weren't considered sufficient on their own here.
"""

import hmac

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from app.core.cookies import CSRF_EXEMPT_PATHS, CSRF_HEADER_NAME, CSRF_TOKEN_COOKIE

_UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


class CSRFMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.method in _UNSAFE_METHODS and request.url.path not in CSRF_EXEMPT_PATHS:
            cookie_value = request.cookies.get(CSRF_TOKEN_COOKIE)
            header_value = request.headers.get(CSRF_HEADER_NAME)
            if (
                not cookie_value
                or not header_value
                or not hmac.compare_digest(cookie_value, header_value)
            ):
                return JSONResponse(
                    status_code=403,
                    content={"detail": "CSRF token missing or invalid"},
                )
        return await call_next(request)
