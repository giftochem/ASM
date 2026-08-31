import uuid
from datetime import datetime

from sqlalchemy import DateTime, Enum, Float, ForeignKey, Index, String, func
from sqlalchemy.dialects.postgresql import JSONB, UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.enums import AssetType, DiscoveryResultOutcome, RelationshipType
from app.models.base import Base, UUIDPKMixin


class DiscoveryResult(Base, UUIDPKMixin):
    """What a provider reported, pre-normalization — including
    candidates that never became an Observation (rejected for failing
    validation, or duplicates). The same "raw evidence vs. narrative
    outcome" split Finding already provides for scans. Immutable once
    written, like Observation/AuditLog: no TimestampMixin/updated_at,
    just created_at.
    """

    __tablename__ = "discovery_results"
    __table_args__ = (Index("ix_discovery_results_discovery_run_id", "discovery_run_id"),)

    discovery_run_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("discovery_runs.id", ondelete="CASCADE"), nullable=False
    )
    candidate_asset_type: Mapped[AssetType] = mapped_column(Enum(AssetType, name="asset_type"), nullable=False)
    # Raw, as the provider reported it — pre-normalization. The
    # normalized form is whatever resulting_asset.value ends up being.
    candidate_value: Mapped[str] = mapped_column(String(255), nullable=False)
    relationship_type: Mapped[RelationshipType | None] = mapped_column(
        Enum(RelationshipType, name="relationship_type"), nullable=True
    )
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    evidence: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    outcome: Mapped[DiscoveryResultOutcome] = mapped_column(
        Enum(DiscoveryResultOutcome, name="discovery_result_outcome"), nullable=False
    )
    resulting_asset_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("assets.id"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    discovery_run = relationship("DiscoveryRun", back_populates="results")
