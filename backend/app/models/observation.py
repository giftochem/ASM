import uuid
from datetime import datetime

from sqlalchemy import DateTime, Enum, Float, ForeignKey, Index, String, Text, func
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.enums import AssetSource, ChangeType
from app.models.base import Base, UUIDPKMixin


class Observation(Base, UUIDPKMixin):
    """An immutable, append-only historical record — preserves what ASM
    believed at a point in time rather than overwriting current state.
    Deliberately no TimestampMixin/updated_at: matches AuditLog's
    existing precedent for a write-once record, which declares its own
    plain `created_at` column directly (UUIDPKMixin provides only `id`).
    `observed_at` is a separate, independently-meaningful timestamp —
    when the fact was true in the world, not when this row was written —
    the same real-world-time-vs-DB-write-time distinction Step 8.1
    already drew between Asset.first_seen and Asset.created_at.

    Asset-scoped only for now, not relationship-scoped — extending this
    to relationships later is a non-breaking addition (a nullable
    relationship_id FK), not something this schema forecloses.
    """

    __tablename__ = "observations"
    __table_args__ = (Index("ix_observations_asset_id_observed_at", "asset_id", "observed_at"),)

    asset_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False
    )
    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    change_type: Mapped[ChangeType] = mapped_column(Enum(ChangeType, name="change_type"), nullable=False)
    field_name: Mapped[str | None] = mapped_column(String(100), nullable=True)
    previous_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    current_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    source: Mapped[AssetSource] = mapped_column(
        Enum(AssetSource, name="asset_source"), nullable=False, default=AssetSource.manual
    )
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    asset = relationship("Asset", back_populates="observations")
