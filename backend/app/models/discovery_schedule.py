import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.enums import AssetType, DiscoveryRunStatus
from app.models.base import Base, TimestampMixin, UUIDPKMixin


class DiscoverySchedule(Base, UUIDPKMixin, TimestampMixin):
    """A persisted intent to run one provider against one seed asset
    repeatedly (Step 9.11) -- the schedule itself carries no execution
    history of its own; every actual attempt is a normal DiscoveryRun
    (via `last_run_id`, and going forward via DiscoveryRun.schedule_id),
    reusing the existing history/observation/change-detection machinery
    entirely unchanged. Not a second history system.

    organization_id is denormalized here (unlike most child tables,
    which reach org-scoping only via a join through Asset) for the exact
    same reason DiscoveryRun already does this: a schedule's scope is
    inherently org-level, and background execution (no request, no
    session, nothing to derive scope from) must always be able to
    re-derive it directly from this row -- never from anything
    caller-supplied.

    `claimed_at` implements the concurrency-safe claim (Step 9.11.2/
    9.11.3): the dispatcher claims a batch of due, unclaimed-or-stale
    schedules via `SELECT ... FOR UPDATE SKIP LOCKED`, creates the
    DiscoveryRun for that attempt in the SAME transaction, and stamps
    `claimed_at`. No separate claim-token is needed: the created
    DiscoveryRun's own `status` is the actual atomicity gate the
    execution task checks before doing any work (an atomic conditional
    `UPDATE ... WHERE status = 'queued'`, exactly mirroring
    scan_executor.execute_scan's proven queued->running transition) --
    the schedule-level `claimed_at` only prevents a SECOND run from
    being created for the same schedule while one is still in flight. A
    claim's staleness (a worker crashed or was killed by Celery's own
    task time limit mid-run) is entirely determined by comparing
    `claimed_at` against a timeout -- no separate reaper process.
    """

    __tablename__ = "discovery_schedules"
    __table_args__ = (
        Index("ix_discovery_schedules_organization_id", "organization_id"),
        Index("ix_discovery_schedules_seed_asset_id", "seed_asset_id"),
        Index("ix_discovery_schedules_next_run_at", "next_run_at"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False
    )
    seed_asset_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("assets.id"), nullable=False
    )
    provider_name: Mapped[str] = mapped_column(String(100), nullable=False)
    created_by: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id"), nullable=False
    )

    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    # A plain integer, not a cron expression -- "the smallest explicit
    # mechanism that is useful" (Step 9.11's own instruction); arbitrary
    # cron syntax is an explicit non-goal for this pass.
    interval_hours: Mapped[int] = mapped_column(Integer, nullable=False)

    next_run_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_run_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("discovery_runs.id"), nullable=True
    )

    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Set (and `enabled` flipped False) when a scheduled execution finds
    # authorization revoked/missing, or a permanently-invalid
    # configuration -- distinguishes "disabled on purpose by a person"
    # from "auto-disabled because it stopped being safe to run" without
    # needing a separate status enum.
    disabled_reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    seed_asset = relationship("Asset", foreign_keys=[seed_asset_id])
    last_run = relationship("DiscoveryRun", foreign_keys=[last_run_id])

    @property
    def seed_asset_value(self) -> str:
        """Step 9.13: denormalized for API responses, mirroring
        ActivityFeedItem's/Alert's identical precedent -- a schedule list
        is useless without the asset's name. Reads the already
        (eager-loaded, see discovery_schedule_service.list_schedules /
        api/routes/discovery.py) `seed_asset` relationship.
        """
        return self.seed_asset.value

    @property
    def seed_asset_type(self) -> AssetType:
        return self.seed_asset.asset_type

    @property
    def last_run_status(self) -> DiscoveryRunStatus | None:
        """None until the schedule has ever run -- reads the already
        eager-loaded `last_run` relationship, never issues its own query.
        """
        return self.last_run.status if self.last_run is not None else None
