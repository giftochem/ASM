import uuid
from datetime import datetime

from sqlalchemy import ARRAY, DateTime, Enum, Float, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.enums import RiskSeverityBand, ScanStatus
from app.models.base import Base, TimestampMixin, UUIDPKMixin


class Scan(Base, UUIDPKMixin, TimestampMixin):
    __tablename__ = "scans"

    asset_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("assets.id"), nullable=False
    )
    initiated_by: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id"), nullable=False
    )
    status: Mapped[ScanStatus] = mapped_column(
        Enum(ScanStatus, name="scan_status"), nullable=False, default=ScanStatus.queued
    )
    modules_requested: Mapped[list[str]] = mapped_column(ARRAY(String(50)), nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Aggregate risk_engine output over this scan's findings, computed once
    # by scan_executor after modules finish. Null until then (queued/
    # running/cancelled scans, or a scan with zero findings never gets a
    # score computed). Not a cached copy of per-finding scores — those are
    # computed on demand from stored severity/exposure/exploitability/
    # confidence, never persisted, so there's one source of truth for the
    # formula (see app/services/risk_engine.py, docs/risk-scoring.md).
    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    risk_severity_band: Mapped[RiskSeverityBand | None] = mapped_column(
        Enum(RiskSeverityBand, name="risk_severity_band"), nullable=True
    )

    asset = relationship("Asset", back_populates="scans")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="scan", cascade="all, delete-orphan")
