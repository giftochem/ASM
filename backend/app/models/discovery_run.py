import uuid
from datetime import datetime

from sqlalchemy import DateTime, Enum, ForeignKey, Index, String, Text
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.enums import DiscoveryRunStatus
from app.models.base import Base, TimestampMixin, UUIDPKMixin


class DiscoveryRun(Base, UUIDPKMixin, TimestampMixin):
    """One execution of one discovery provider against one seed asset.
    Mirrors Scan's shape closely (asset/initiated_by/status/timestamps/
    error) but stays a genuinely separate table — passive discovery and
    active scanning are deliberately distinct concerns in this product,
    not one thing wearing two names.

    organization_id is denormalized here (unlike most child tables,
    which reach org-scoping only via a join through Asset) because a
    run's scope is inherently org-level even with a single seed asset —
    same reasoning as AuditLog carrying organization_id directly.

    seed_asset_id has no ondelete=CASCADE: this is an audit-quality
    historical record (which provider ran, when, with what outcome) that
    shouldn't silently vanish if the seed asset is ever removed later —
    matches AuditLog's FK style, not AssetRelationship's.
    """

    __tablename__ = "discovery_runs"
    __table_args__ = (
        Index("ix_discovery_runs_organization_id", "organization_id"),
        Index("ix_discovery_runs_seed_asset_id", "seed_asset_id"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False
    )
    seed_asset_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("assets.id"), nullable=False
    )
    initiated_by: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id"), nullable=False
    )
    provider_name: Mapped[str] = mapped_column(String(100), nullable=False)
    # Nullable: most runs are still manually triggered and have no
    # schedule. Step 9.11 -- lets a run answer "which schedule produced
    # this," reusing this existing table rather than a second history
    # system. No ondelete=CASCADE, matching seed_asset_id's own choice
    # just above: a run is an audit-quality record that must survive
    # its originating schedule being deleted later.
    #
    # discovery_schedules.last_run_id points back at this table, so the
    # two tables have a genuine mutual FK reference -- use_alter=True
    # (with an explicit constraint name, required for use_alter) tells
    # SQLAlchemy to add/drop this specific constraint via a separate
    # ALTER TABLE rather than trying to include it in CREATE/DROP TABLE,
    # which is what actually breaks the circular dependency for
    # Base.metadata.create_all/drop_all (used by the test suite; Alembic
    # migrations were never affected by this, since 0013 already creates
    # discovery_schedules before adding this column via its own explicit
    # ALTER TABLE step).
    schedule_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("discovery_schedules.id", use_alter=True, name="fk_discovery_runs_schedule_id"),
        nullable=True,
    )
    status: Mapped[DiscoveryRunStatus] = mapped_column(
        Enum(DiscoveryRunStatus, name="discovery_run_status"),
        nullable=False,
        default=DiscoveryRunStatus.queued,
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    seed_asset = relationship("Asset", back_populates="discovery_runs_as_seed")
    results = relationship("DiscoveryResult", back_populates="discovery_run", cascade="all, delete-orphan")
