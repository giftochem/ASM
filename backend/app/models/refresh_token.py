import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, UUIDPKMixin


class RefreshToken(Base, UUIDPKMixin):
    """Server-side state for refresh-token rotation/revocation. `id` here
    IS the `jti` claim embedded in the corresponding refresh JWT — the JWT
    signature proves authenticity, this row tracks whether that specific
    token is still valid (single-use: rotated on every refresh, revoked on
    logout, all-revoked on detected reuse). No TimestampMixin/updated_at —
    a row is written once and only ever gets `revoked_at` set later.
    """

    __tablename__ = "refresh_tokens"

    user_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id"), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
