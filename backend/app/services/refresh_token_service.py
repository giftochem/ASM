"""Refresh-token lifecycle: issue, rotate (single-use), revoke, and
reuse-detection. This is what makes cookie-based refresh tokens actually
revocable — the JWT signature alone only proves authenticity, never
whether a specific token has since been logged-out or superseded.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import update
from sqlalchemy.orm import Session

from app.models.refresh_token import RefreshToken
from app.security import create_refresh_token, decode_refresh_token


class RefreshTokenError(Exception):
    def __init__(self, reason: str, user_id: uuid.UUID | None = None):
        self.reason = reason
        self.user_id = user_id
        super().__init__(reason)


def issue(db: Session, user_id: uuid.UUID) -> str:
    token, jti, expires_at = create_refresh_token(user_id)
    db.add(
        RefreshToken(
            id=jti,
            user_id=user_id,
            created_at=datetime.now(timezone.utc),
            expires_at=expires_at,
        )
    )
    db.commit()
    return token


def rotate(db: Session, presented_token: str) -> tuple[str, uuid.UUID]:
    """Validates and single-use-rotates a refresh token. Raises
    RefreshTokenError for every invalid case — callers translate that to
    401 and clear cookies. A presented token whose row is already revoked
    is treated as a compromise signal (rotation means a legitimate client
    never re-presents an already-rotated token): every other active
    refresh token for that user is revoked too, forcing a full re-login.
    """
    try:
        user_id, jti = decode_refresh_token(presented_token)
    except Exception as exc:
        raise RefreshTokenError("invalid_token") from exc

    row = db.get(RefreshToken, jti)
    if row is None:
        raise RefreshTokenError("unknown_token", user_id=user_id)

    now = datetime.now(timezone.utc)

    if row.expires_at < now:
        raise RefreshTokenError("expired", user_id=user_id)

    if row.user_id != user_id:
        # Should be unreachable given JWT integrity (sub and jti are both
        # signed), but never trust a single check alone for an auth path.
        raise RefreshTokenError("subject_mismatch", user_id=user_id)

    # Atomic conditional UPDATE, not read-then-write (Step 7A
    # remediation, finding M-1): the previous code read row.revoked_at,
    # then separately wrote it, leaving a window where two concurrent
    # requests presenting the same still-valid token could both pass the
    # read check before either committed, both minting new tokens from
    # one presented token. This WHERE clause makes Postgres the arbiter
    # of which of any concurrent rotate() calls for this jti actually
    # wins — rowcount == 0 means another request already revoked it first
    # (reuse, or a concurrent legitimate rotation), handled exactly like
    # the old explicit "already revoked" check was.
    result = db.execute(
        update(RefreshToken)
        .where(RefreshToken.id == jti, RefreshToken.revoked_at.is_(None))
        .values(revoked_at=now)
    )
    db.commit()

    if result.rowcount == 0:
        revoke_all_for_user(db, row.user_id)
        raise RefreshTokenError("reuse_detected", user_id=row.user_id)

    new_token = issue(db, user_id)
    return new_token, user_id


def revoke(db: Session, presented_token: str) -> None:
    """Used by logout. Tolerant of an already-invalid/expired/unknown
    token — logging out must always succeed from the client's point of
    view, it just has nothing further to do server-side in that case.
    """
    try:
        _, jti = decode_refresh_token(presented_token)
    except Exception:
        return

    row = db.get(RefreshToken, jti)
    if row is not None and row.revoked_at is None:
        row.revoked_at = datetime.now(timezone.utc)
        db.commit()


def revoke_all_for_user(db: Session, user_id: uuid.UUID) -> None:
    db.execute(
        update(RefreshToken)
        .where(RefreshToken.user_id == user_id, RefreshToken.revoked_at.is_(None))
        .values(revoked_at=datetime.now(timezone.utc))
    )
    db.commit()
