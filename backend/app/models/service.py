import uuid
from datetime import datetime

from sqlalchemy import DateTime, Enum, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.enums import AssetSource, LifecycleStatus
from app.models.base import Base, TimestampMixin, UUIDPKMixin


class Service(Base, UUIDPKMixin, TimestampMixin):
    """Deduped current-state service inventory per asset — what Steps
    9-12 (discovery, fingerprinting, exposure detection) will populate
    and update as scanning runs repeatedly. Distinct from
    PortScanResult, which stays a historical, append-only record of
    what one specific scan observed.
    """

    __tablename__ = "services"
    __table_args__ = (
        UniqueConstraint("asset_id", "port", "protocol", name="uq_service_asset_port_protocol"),
    )

    asset_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("assets.id"), nullable=False
    )
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String(10), nullable=False, default="tcp")
    service_name: Mapped[str | None] = mapped_column(String(100), nullable=True)
    product: Mapped[str | None] = mapped_column(String(255), nullable=True)
    version: Mapped[str | None] = mapped_column(String(100), nullable=True)
    banner: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[LifecycleStatus] = mapped_column(
        Enum(LifecycleStatus, name="lifecycle_status"), nullable=False, default=LifecycleStatus.active
    )
    source: Mapped[AssetSource] = mapped_column(
        Enum(AssetSource, name="asset_source"), nullable=False, default=AssetSource.manual
    )
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    asset = relationship("Asset", back_populates="services")
