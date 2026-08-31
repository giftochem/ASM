"""Rate limiting: enforcement, and the fail-closed behavior when the
Redis-backed limiter storage is unreachable.

Note: the fail-closed handler's LOGIC is verified directly here
(test_redis_unavailable_handler_returns_503), which is deterministic and
doesn't depend on third-party library internals. Actually taking Redis
down mid-suite and confirming slowapi/limits itself raises the exception
that reaches that handler was verified manually (docker compose stop
redis, curl a rate-limited endpoint, confirm 503, docker compose start
redis) rather than automated here — doing that from within the pytest
process would leave the shared dev Redis instance stopped for every other
test in the same run (including the real Celery integration test), which
is worse than the coverage gap it would close.
"""

import asyncio
import json

import redis

from app.config import settings
from app.main import _redis_unavailable_handler


def test_redis_unavailable_handler_returns_503_not_500_or_silent_pass():
    exc = redis.exceptions.ConnectionError("simulated redis outage")
    response = asyncio.run(_redis_unavailable_handler(None, exc))

    assert response.status_code == 503
    body = json.loads(response.body)
    assert "unavailable" in body["detail"].lower()


def test_login_rate_limit_is_enforced(client):
    limit = int(settings.rate_limit_login.split("/")[0])

    for _ in range(limit):
        resp = client.post(
            "/auth/login", data={"username": "nobody@example.com", "password": "wrong"}
        )
        assert resp.status_code == 401

    over_limit_resp = client.post(
        "/auth/login", data={"username": "nobody@example.com", "password": "wrong"}
    )
    assert over_limit_resp.status_code == 429


def test_register_rate_limit_is_enforced(client):
    limit = int(settings.rate_limit_login.split("/")[0])

    for i in range(limit):
        client.post(
            "/auth/register",
            json={
                "organization_name": f"Rate Limit Org {i}",
                "email": f"ratelimit{i}@example.com",
                "password": "correct-horse-battery",
                "full_name": "Rate Limited",
            },
        )

    over_limit_resp = client.post(
        "/auth/register",
        json={
            "organization_name": "One Too Many",
            "email": "onetoomanyxyz@example.com",
            "password": "correct-horse-battery",
            "full_name": "Rate Limited",
        },
    )
    assert over_limit_resp.status_code == 429


def test_rate_limit_is_per_route_not_global(client, register_user):
    """Exhausting the login limit must not block unrelated, non-rate-limited
    endpoints for the same caller.
    """
    limit = int(settings.rate_limit_login.split("/")[0])
    headers = register_user()

    for _ in range(limit + 1):
        client.post("/auth/login", data={"username": "nobody2@example.com", "password": "wrong"})

    resp = client.get("/users/me", headers=headers)
    assert resp.status_code == 200
