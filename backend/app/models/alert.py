import uuid
from datetime import datetime

from sqlalchemy import DateTime, Enum, ForeignKey, Index, Integer, String, Text, text
from sqlalchemy.dialects.postgresql import JSONB, UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.enums import AlertPriority, AlertStatus, AlertType, AssetType
from app.models.base import Base, TimestampMixin, UUIDPKMixin


class Alert(Base, UUIDPKMixin, TimestampMixin):
    """Step 9.12 -- "this deserves attention," derived from Observations
    the existing normalization pipeline already wrote (see
    app.services.alert_service's module docstring for the full
    reasoning and the one exception, authorization_disabled).
    Deliberately NOT a second change-detection or history system: an
    Alert never records a fact about the world on its own -- it always
    points back at the Observation (or, for authorization_disabled, the
    DiscoveryRun) that justified it via source_observation_id/
    discovery_run_id, and its own row IS the full lifecycle history
    (first_seen_at/last_seen_at/occurrence_count/acknowledged_*/
    resolved_*) -- no separate audit table, matching DiscoverySchedule's
    identical choice (Step 9.11) to track its own history inline rather
    than in a second table.

    organization_id is denormalized (not reached only via asset_id) for
    the same reason DiscoveryRun/DiscoverySchedule already do this:
    asset_id is nullable (a hypothetical future alert type might not be
    asset-scoped), and every alert query needs to be org-scoped
    directly and cheaply regardless of which optional FK is populated.
    """

    __tablename__ = "alerts"
    __table_args__ = (
        Index("ix_alerts_organization_id", "organization_id"),
        Index("ix_alerts_organization_id_status", "organization_id", "status"),
        Index("ix_alerts_asset_id", "asset_id"),
        # Step 9.12.16: the real, PostgreSQL-enforced concurrency
        # guarantee -- at most one OPEN-OR-ACKNOWLEDGED alert may exist
        # per (organization_id, fingerprint) at a time. A resolved alert
        # is deliberately excluded from this constraint (see
        # alert_service._create_or_update_alert): the same condition
        # recurring after resolution must be able to create a genuinely
        # NEW alert row, preserving the resolved one's history
        # untouched, rather than being blocked or forced to reopen it.
        Index(
            "uq_alerts_org_fingerprint_open",
            "organization_id",
            "fingerprint",
            unique=True,
            postgresql_where=text("status != 'resolved'"),
        ),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False
    )
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=True
    )
    relationship_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("asset_relationships.id", ondelete="SET NULL"), nullable=True
    )
    discovery_run_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("discovery_runs.id", ondelete="SET NULL"), nullable=True
    )
    source_observation_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("observations.id", ondelete="SET NULL"), nullable=True
    )

    alert_type: Mapped[AlertType] = mapped_column(Enum(AlertType, name="alert_type"), nullable=False)
    priority: Mapped[AlertPriority] = mapped_column(Enum(AlertPriority, name="alert_priority"), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    evidence: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    status: Mapped[AlertStatus] = mapped_column(
        Enum(AlertStatus, name="alert_status"), nullable=False, default=AlertStatus.open
    )

    # Deterministic, semantic dedup identity (organization + alert_type
    # + the event's own identity, e.g. asset_id, sometimes + a slot like
    # hostname:port) -- never a timestamp, never a database id. See
    # app.services.alert_service._fingerprint. A sha256 hex digest
    # (fixed 64 chars), not the raw identity string, so it's opaque and
    # bounded regardless of how many parts go into it.
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)

    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    occurrence_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    acknowledged_by: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id"), nullable=True
    )
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resolved_by: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id"), nullable=True
    )

    asset = relationship("Asset")
    relationship_ref = relationship("AssetRelationship")
    discovery_run = relationship("DiscoveryRun")

    @property
    def asset_value(self) -> str | None:
        """Step 9.13: denormalized for API responses, mirroring
        ActivityFeedItem's identical precedent (graph_service) -- a list
        of alerts is useless without knowing which asset each one is
        about, and forcing the frontend to look that up per-row would be
        the exact N+1 this property avoids. Reads the already
        (eager-loaded, see alert_service.list_alerts /
        api/routes/alerts.py) `asset` relationship -- never issues its
        own query.
        """
        return self.asset.value if self.asset is not None else None

    @property
    def asset_type(self) -> AssetType | None:
        return self.asset.asset_type if self.asset is not None else None
    source_observation = relationship("Observation")
