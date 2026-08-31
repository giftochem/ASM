import uuid
from datetime import datetime

from sqlalchemy import DateTime, Enum, ForeignKey, String, func
from sqlalchemy.dialects.postgresql import JSONB, UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.enums import AuditOutcome
from app.models.base import Base, UUIDPKMixin


class AuditLog(Base, UUIDPKMixin):
    """Write-only audit trail. No TimestampMixin/updated_at here — audit
    rows are immutable once written.

    `details` (JSONB) is for free-form, action-specific context — never put
    passwords, JWTs/refresh tokens, CSRF tokens, or any other secret in it.
    Every call site in this codebase must only ever pass identifiers,
    booleans, counts, and short descriptive strings there.
    """

    __tablename__ = "audit_logs"

    user_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id"), nullable=True
    )
    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("organizations.id"), nullable=True
    )
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(50), nullable=False)
    resource_id: Mapped[uuid.UUID | None] = mapped_column(PGUUID(as_uuid=True), nullable=True)
    outcome: Mapped[AuditOutcome] = mapped_column(
        Enum(AuditOutcome, name="audit_outcome"), nullable=False, default=AuditOutcome.success
    )
    details: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    # Plain string, not Postgres INET: the source value (request.client.host
    # from the ASGI scope) isn't always a strict IP — Starlette's TestClient
    # sends the literal string "testclient", and some proxy configs can
    # forward non-IP identifiers too. Audit logging must never fail the
    # primary write it's attached to just because of that.
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
