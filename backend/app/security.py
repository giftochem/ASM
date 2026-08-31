import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Literal
from uuid import UUID, uuid4

from jose import JWTError, jwt
from passlib.context import CryptContext

from app.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

TokenType = Literal["access", "refresh"]


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, password_hash: str) -> bool:
    return pwd_context.verify(plain_password, password_hash)


# Precomputed once at import time so a login attempt against a nonexistent
# email pays the same bcrypt cost as a real password check (see
# app.api.routes.auth.login). Without this, "user is None" would
# short-circuit verify_password entirely, and the resulting timing gap
# would let an attacker distinguish "no such account" from "wrong
# password" despite both returning an identical error message and status
# code (Step 7A remediation, finding H-1). The value itself is never
# compared against anything real -- only its presence as a valid bcrypt
# hash for verify_password to run against matters.
DUMMY_PASSWORD_HASH = pwd_context.hash("not-a-real-password-used-only-for-constant-time-login-checks")


def _create_token(
    subject: UUID, token_type: TokenType, expires_delta: timedelta, jti: UUID | None = None
) -> tuple[str, datetime]:
    now = datetime.now(timezone.utc)
    expires_at = now + expires_delta
    payload: dict[str, Any] = {
        "sub": str(subject),
        "type": token_type,
        "iat": now,
        "exp": expires_at,
    }
    if jti is not None:
        payload["jti"] = str(jti)
    token = jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)
    return token, expires_at


def create_access_token(user_id: UUID) -> str:
    token, _ = _create_token(user_id, "access", timedelta(minutes=settings.access_token_expire_minutes))
    return token


def create_refresh_token(user_id: UUID, jti: UUID | None = None) -> tuple[str, UUID, datetime]:
    """Refresh tokens always carry a `jti` (generated here if not supplied)
    so app.services.refresh_token_service can track per-token state
    (rotation, revocation, reuse detection) — access tokens deliberately
    don't have this, staying fully stateless for the hot path.
    """
    jti = jti or uuid4()
    token, expires_at = _create_token(
        user_id, "refresh", timedelta(days=settings.refresh_token_expire_days), jti=jti
    )
    return token, jti, expires_at


def decode_token(token: str, expected_type: TokenType) -> UUID:
    """Decode and validate a JWT, returning the subject user id.

    Raises jose.JWTError (or ValueError for a type mismatch) on any
    invalid/expired/wrong-type token — callers translate that into a 401.
    """
    payload = jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
    if payload.get("type") != expected_type:
        raise ValueError(f"expected a {expected_type} token")
    return UUID(payload["sub"])


def decode_refresh_token(token: str) -> tuple[UUID, UUID]:
    """Like decode_token, but also returns the jti — every refresh token
    must carry one; a refresh JWT without one is treated as invalid rather
    than silently accepted, since it couldn't be tracked for revocation.
    """
    payload = jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
    if payload.get("type") != "refresh":
        raise ValueError("expected a refresh token")
    jti = payload.get("jti")
    if not jti:
        raise ValueError("refresh token missing jti")
    return UUID(payload["sub"]), UUID(jti)


def generate_csrf_token() -> str:
    """Not a JWT — the double-submit CSRF pattern's security comes from an
    attacker being unable to *read* this value cross-origin (it's just an
    unguessable opaque token in a cookie), not from any cryptographic
    property of the token itself.
    """
    return secrets.token_urlsafe(32)


__all__ = [
    "hash_password",
    "verify_password",
    "DUMMY_PASSWORD_HASH",
    "create_access_token",
    "create_refresh_token",
    "decode_token",
    "decode_refresh_token",
    "generate_csrf_token",
    "JWTError",
]
