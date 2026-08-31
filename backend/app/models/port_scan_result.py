import uuid

from sqlalchemy import ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, UUIDPKMixin


class PortScanResult(Base, UUIDPKMixin, TimestampMixin):
    """Structured output of the port_scanner module, alongside its
    narrative Finding rows — same pattern as DNSRecord/SSLInfo/Technology.
    """

    __tablename__ = "port_scan_results"

    asset_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("assets.id"), nullable=False
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("scans.id"), nullable=False
    )
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String(10), nullable=False, default="tcp")
    # "open" | "closed" | "filtered" — a TCP-connect scan distinguishes a
    # fast ECONNREFUSED (closed) from a timeout (filtered/firewalled),
    # which is a meaningful signal worth keeping even without a raw SYN scan.
    state: Mapped[str] = mapped_column(String(20), nullable=False)

    asset = relationship("Asset")
