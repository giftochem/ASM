"""Rate limiting via slowapi, backed by the same Redis instance Celery
uses. Deliberately fails CLOSED: if Redis is unreachable, requests to a
rate-limited endpoint are rejected (503), never silently let through
uncounted. See the redis.exceptions.RedisError handler registered in
app.main — that's what turns a storage-backend outage into an explicit
503 instead of either an unhandled 500 or (much worse) rate limiting
quietly doing nothing.
"""

from fastapi import Request
from slowapi import Limiter

from app.config import settings
from app.core.client_ip import get_client_ip


def _rate_limit_key(request: Request) -> str:
    return get_client_ip(request) or "unknown"


limiter = Limiter(key_func=_rate_limit_key, storage_uri=settings.redis_url)
