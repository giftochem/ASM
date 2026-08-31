import uuid
from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.enums import AssetSource, LifecycleStatus, RelationshipType
from app.models.base import Base, TimestampMixin, UUIDPKMixin


class AssetRelationship(Base, UUIDPKMixin, TimestampMixin):
    """The Asset Graph backbone (Step 8, revised) — an adjacency-list edge
    between two assets, deliberately plain Postgres rows rather than a
    graph database: sufficient for per-organization attack-surface graphs
    at ASM's scale, traversed via recursive CTEs. Reuses LifecycleStatus/
    AssetSource from Step 8.1 rather than inventing new types — a
    relationship is exactly the same "thing ASM currently believes is
    true, that can appear/go stale/disappear" shape those enums already
    model for Asset/Service/Certificate.
    """

    __tablename__ = "asset_relationships"
    __table_args__ = (
        UniqueConstraint(
            "source_asset_id", "target_asset_id", "relationship_type",
            name="uq_relationship_source_target_type",
        ),
        CheckConstraint("source_asset_id != target_asset_id", name="ck_relationship_no_self_reference"),
        Index("ix_asset_relationships_target_asset_id", "target_asset_id"),
    )

    source_asset_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False
    )
    target_asset_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False
    )
    relationship_type: Mapped[RelationshipType] = mapped_column(
        Enum(RelationshipType, name="relationship_type"), nullable=False
    )
    status: Mapped[LifecycleStatus] = mapped_column(
        Enum(LifecycleStatus, name="lifecycle_status"), nullable=False, default=LifecycleStatus.active
    )
    source: Mapped[AssetSource] = mapped_column(
        Enum(AssetSource, name="asset_source"), nullable=False, default=AssetSource.manual
    )
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    # No organization_id column, matching every other child table's
    # convention — but unlike a simple asset_id-only child table, both
    # ends here belong to (potentially different) organizations by
    # construction. The join-through-Asset convention alone isn't
    # sufficient: app.services.asset_relationship_service explicitly
    # verifies both assets share the requesting org before a row is ever
    # created, since this is exactly the kind of gap the IDOR regression
    # suite exists to catch.
    source_asset = relationship("Asset", foreign_keys=[source_asset_id], back_populates="outgoing_relationships")
    target_asset = relationship("Asset", foreign_keys=[target_asset_id], back_populates="incoming_relationships")
