import redis
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.api.routes import api_router
from app.config import settings
from app.core.csrf_middleware import CSRFMiddleware
from app.services.rate_limit import limiter

API_DESCRIPTION = """
Attack Surface Mapper (ASM) API — discovers, inventories, analyzes, and
reports on an organization's externally visible assets.

## Authorization & scope disclaimer

This is a defensive security tool for **authorized use only**. You must
own the assets you scan, or hold explicit written permission (e.g. a
signed pentest/MSSP engagement) to test them.

Every asset requires an explicit `authorization_confirmed` confirmation
(`POST /assets/{id}/confirm-authorization`) before any scan — passive or
active — can run against it. This check is enforced server-side in
`app.services.scan_service` and `app.services.scan_executor` (re-checked
immediately before execution, fail-closed) and cannot be bypassed via the
API. Scanning systems without authorization may violate the Computer
Fraud and Abuse Act (US), the Computer Misuse Act (UK), or equivalent
laws elsewhere.

## Authentication

Session tokens are delivered exclusively via httpOnly cookies — never in
a response body, never readable by frontend JavaScript. State-changing
requests require a matching `X-CSRF-Token` header (double-submit cookie
pattern). See docs/auth-cookie-model.md for the full model.
"""

app = FastAPI(
    title="Attack Surface Mapper API",
    description=API_DESCRIPTION,
    version="0.9.0-beta",
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


@app.exception_handler(redis.exceptions.RedisError)
async def _redis_unavailable_handler(request: Request, exc: redis.exceptions.RedisError) -> JSONResponse:
    """Rate limiting fails CLOSED: if the Redis-backed limiter can't be
    reached, the request is rejected rather than silently let through
    uncounted (which would be an accidental, unannounced rate-limiting
    outage) or allowed to crash as a raw unhandled 500.
    """
    return JSONResponse(
        status_code=503,
        content={"detail": "Service temporarily unavailable (rate limiting backend unreachable)"},
    )


app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(CSRFMiddleware)

app.include_router(api_router)


@app.get("/health", tags=["health"])
def health() -> dict[str, str]:
    return {"status": "ok"}
