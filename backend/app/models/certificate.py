import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Enum, Float, ForeignKey, Index, Integer, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import ARRAY, UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.enums import AssetSource, LifecycleStatus
from app.models.base import Base, TimestampMixin, UUIDPKMixin


class Certificate(Base, UUIDPKMixin, TimestampMixin):
    """Deduped current-state certificate per asset+hostname+port — the
    same "intelligence" role Service plays for ports. SSLInfo remains
    the historical, append-only per-scan evidence table; this is not a
    replacement for it.
    """

    __tablename__ = "certificates"
    __table_args__ = (
        UniqueConstraint("asset_id", "hostname", "port", name="uq_certificate_asset_hostname_port"),
        Index("ix_certificates_fingerprint_sha256", "fingerprint_sha256"),
    )

    asset_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("assets.id"), nullable=False
    )
    hostname: Mapped[str] = mapped_column(String(255), nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False, default=443)
    issuer: Mapped[str | None] = mapped_column(String(500), nullable=True)
    subject: Mapped[str | None] = mapped_column(String(500), nullable=True)
    valid_from: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    valid_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    serial_number: Mapped[str | None] = mapped_column(String(100), nullable=True)
    # Not present on SSLInfo — a real identity key for "is this the same
    # certificate we saw before," which issuer/subject strings alone
    # can't reliably answer (both can legitimately repeat across a
    # renewal).
    fingerprint_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    signature_algorithm: Mapped[str | None] = mapped_column(String(100), nullable=True)
    protocol_version: Mapped[str | None] = mapped_column(String(20), nullable=True)
    cipher_suite: Mapped[str | None] = mapped_column(String(100), nullable=True)
    subject_alt_names: Mapped[list[str] | None] = mapped_column(ARRAY(String(255)), nullable=True)
    is_expired: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_self_signed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # Step 9.3. Stored as a string ("v3"), not an int -- X.509's internal
    # encoding is 0-indexed (v1=0, v3=2), which doesn't match how anyone
    # actually refers to cert versions; cryptography's own cert.version.name
    # already gives the human form directly.
    certificate_version: Mapped[str | None] = mapped_column(String(10), nullable=True)
    public_key_algorithm: Mapped[str | None] = mapped_column(String(50), nullable=True)
    public_key_size: Mapped[int | None] = mapped_column(Integer, nullable=True)
    status: Mapped[LifecycleStatus] = mapped_column(
        Enum(LifecycleStatus, name="lifecycle_status"), nullable=False, default=LifecycleStatus.active
    )
    source: Mapped[AssetSource] = mapped_column(
        Enum(AssetSource, name="asset_source"), nullable=False, default=AssetSource.manual
    )
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    asset = relationship("Asset", back_populates="certificates")
