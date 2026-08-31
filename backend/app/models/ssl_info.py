import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import ARRAY, UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, UUIDPKMixin


class SSLInfo(Base, UUIDPKMixin, TimestampMixin):
    __tablename__ = "ssl_info"

    asset_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("assets.id"), nullable=False
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("scans.id"), nullable=False
    )
    hostname: Mapped[str] = mapped_column(String(255), nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False, default=443)
    issuer: Mapped[str | None] = mapped_column(String(500), nullable=True)
    subject: Mapped[str | None] = mapped_column(String(500), nullable=True)
    valid_from: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    valid_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    serial_number: Mapped[str | None] = mapped_column(String(100), nullable=True)
    signature_algorithm: Mapped[str | None] = mapped_column(String(100), nullable=True)
    protocol_version: Mapped[str | None] = mapped_column(String(20), nullable=True)
    cipher_suite: Mapped[str | None] = mapped_column(String(100), nullable=True)
    subject_alt_names: Mapped[list[str] | None] = mapped_column(ARRAY(String(255)), nullable=True)
    is_expired: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_self_signed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    asset = relationship("Asset", back_populates="ssl_info_entries")
