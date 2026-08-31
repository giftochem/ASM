"""Account-based brute-force protection, independent of and complementary
to the IP-based rate limiter in app.services.rate_limit. Keyed by
normalized email, so it catches an attacker distributing guesses across
many source IPs against one account — something the IP limiter alone
cannot see. Added in the Step 7A remediation (finding H-3).

Design:
- Failures are recorded identically for real AND nonexistent email
  addresses (see the call sites in app.api.routes.auth.login) — otherwise
  "does this account ever lock?" becomes a new user-enumeration
  side-channel, undoing the H-1 timing-attack fix.
- Temporary and self-expiring, never permanent: a lock always clears on
  its own once its Redis-TTL-bound duration elapses. Repeated offenses
  escalate that duration (capped) rather than accumulate into a
  permanent lock — an attacker cannot weaponize this into a lasting
  denial-of-service against a victim's own account.
- Concurrency-safe via Redis's atomic INCR / SET NX EX, not any
  application-level locking — safe under simultaneous login attempts by
  construction, not by added coordination.
- Fails CLOSED: a redis.exceptions.RedisError here is deliberately not
  caught — it propagates to the same handler that already turns a
  rate-limiter Redis outage into a 503 (see app.main), so an unreachable
  Redis blocks login rather than silently disabling brute-force
  protection.
"""

import redis

from app.config import settings

# 10 failures within 15 minutes triggers a lock. Deliberately generous
# (not a hair-trigger 3-5) so a legitimate user fumbling their password a
# few times never trips this — it exists to stop sustained guessing, not
# to punish typos.
_FAILURE_THRESHOLD = 10
_FAILURE_WINDOW_SECONDS = 15 * 60

# Lockout duration escalates with repeated offenses (60s, 120s, 240s, ...)
# but is always capped at 1 hour and always self-expires — never
# permanent. The escalation level itself forgets itself after a day of no
# further offenses, and resets immediately on any successful login.
_LOCKOUT_BASE_SECONDS = 60
_LOCKOUT_MAX_SECONDS = 60 * 60
_ESCALATION_WINDOW_SECONDS = 24 * 60 * 60

_client = redis.Redis.from_url(settings.redis_url)


def _normalize(email: str) -> str:
    return email.strip().lower()


def _failure_key(email: str) -> str:
    return f"login_lockout:failures:{_normalize(email)}"


def _lock_key(email: str) -> str:
    return f"login_lockout:locked:{_normalize(email)}"


def _escalation_key(email: str) -> str:
    return f"login_lockout:escalation:{_normalize(email)}"


def seconds_locked(email: str) -> int | None:
    """Returns remaining lockout seconds if `email` is currently locked,
    else None. Call before attempting password verification, so a locked
    account doesn't also pay a bcrypt cost on every hammered attempt.
    """
    ttl = _client.ttl(_lock_key(email))
    return ttl if ttl and ttl > 0 else None


def record_failure(email: str) -> None:
    """Call for every failed login attempt — a real account with the
    wrong password, and a nonexistent email, alike (see module
    docstring). Atomically increments the failure counter; once the
    threshold is reached within the window, sets a temporary lock whose
    duration escalates with repeated offenses.
    """
    key = _failure_key(email)
    count = _client.incr(key)
    if count == 1:
        _client.expire(key, _FAILURE_WINDOW_SECONDS)

    if count >= _FAILURE_THRESHOLD:
        escalation_key = _escalation_key(email)
        level = _client.incr(escalation_key)
        _client.expire(escalation_key, _ESCALATION_WINDOW_SECONDS)
        lockout_seconds = min(_LOCKOUT_BASE_SECONDS * (2 ** (level - 1)), _LOCKOUT_MAX_SECONDS)
        # SET ... NX EX is a single atomic Redis command: concurrent
        # requests racing to trigger the lock can't double-lock, and
        # can't clobber an already-set TTL from a request that won the race.
        _client.set(_lock_key(email), "1", nx=True, ex=lockout_seconds)
        _client.delete(key)


def record_success(email: str) -> None:
    """Full reset on successful authentication — clears the failure
    counter and the escalation level, so a legitimate login doesn't leave
    residual state that makes some future false-alarm lockout longer than
    it needs to be.
    """
    _client.delete(_failure_key(email), _escalation_key(email), _lock_key(email))
