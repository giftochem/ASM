import uuid

from sqlalchemy import Enum, Float, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.enums import FindingSeverity
from app.models.base import Base, TimestampMixin, UUIDPKMixin


class Finding(Base, UUIDPKMixin, TimestampMixin):
    __tablename__ = "findings"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("scans.id"), nullable=False
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("assets.id"), nullable=False
    )
    module: Mapped[str] = mapped_column(String(50), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Raw severity opinion from the module that produced this finding.
    # The Phase 2 risk engine combines this with exposure/exploitability/
    # confidence into a numeric score — see docs/risk-scoring.md (added in
    # Phase 2) — rather than treating this field as the final answer.
    severity: Mapped[FindingSeverity] = mapped_column(
        Enum(FindingSeverity, name="finding_severity"), nullable=False, default=FindingSeverity.info
    )
    # All three risk_engine inputs below are supplied by the module that
    # produced the finding (see scanners/base.ScanFinding) and are always
    # populated — never left to the risk engine to default silently.
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    # How directly internet-reachable the affected surface is, in [0, 1].
    # Phase 1/2 modules only ever look at externally-visible targets, so
    # this defaults to 1.0 (fully exposed); it exists as a per-finding
    # field so a future module (e.g. a port scanner finding an
    # internal-facing-but-reachable service) can differentiate.
    exposure: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    # How easily this specific finding could be leveraged by an attacker,
    # in [0, 1], judged by the module author per finding (e.g. an expired
    # TLS cert is more directly exploitable than a missing Referrer-Policy
    # header).
    exploitability: Mapped[float] = mapped_column(Float, nullable=False, default=0.5)
    evidence: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    scan = relationship("Scan", back_populates="findings")
    asset = relationship("Asset")
