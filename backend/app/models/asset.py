import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Enum, Float, ForeignKey, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import ARRAY, UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship, validates

from app.core.enums import AssetCriticality, AssetEnvironment, AssetSource, AssetType, LifecycleStatus
from app.core.validation import normalize_hostname
from app.models.base import Base, TimestampMixin, UUIDPKMixin


class Asset(Base, UUIDPKMixin, TimestampMixin):
    __tablename__ = "assets"
    __table_args__ = (
        UniqueConstraint("organization_id", "asset_type", "value", name="uq_asset_org_type_value"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False
    )
    asset_type: Mapped[AssetType] = mapped_column(Enum(AssetType, name="asset_type"), nullable=False)
    value: Mapped[str] = mapped_column(String(255), nullable=False)

    # Self-referential FK for future discovery pipelines (e.g. a subdomain
    # found via cert-transparency lookups under a root domain). Unused in
    # Phase 1 — every asset is manually created with parent_asset_id=None —
    # but added now so that adding automated discovery later doesn't
    # require a schema migration + backfill.
    parent_asset_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("assets.id"), nullable=True
    )

    # --- Authorization guardrail ---
    # No scan may run against an asset until this is True. Set explicitly
    # via the API by a user attesting they own or are authorized to test
    # this target. Deliberately NOT dynamically inherited from a parent
    # asset: if a parent's authorization is later revoked, previously
    # created child assets must not silently remain scannable. Any future
    # auto-discovery of child assets should copy the parent's value at
    # creation time instead.
    authorization_confirmed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    authorization_confirmed_by: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id"), nullable=True
    )
    authorization_confirmed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    # --- Step 8.1: Asset Intelligence ---
    # `status` (observation-based lifecycle) is deliberately orthogonal to
    # `is_active` (an admin kill-switch, existing) — a stale-but-not-
    # deactivated asset and a deliberately-disabled-but-still-active-on-
    # the-wire asset are different things. A manually created asset
    # defaults straight to `active`, not `first_seen`: creating one via
    # the API is a deliberate, confirmed action, not a tentative single
    # observation. `first_seen` is for future discovery-created rows
    # (Step 9+).
    status: Mapped[LifecycleStatus] = mapped_column(
        Enum(LifecycleStatus, name="lifecycle_status"), nullable=False, default=LifecycleStatus.active
    )
    source: Mapped[AssetSource] = mapped_column(
        Enum(AssetSource, name="asset_source"), nullable=False, default=AssetSource.manual
    )
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    environment: Mapped[AssetEnvironment | None] = mapped_column(
        Enum(AssetEnvironment, name="asset_environment"), nullable=True
    )
    # Unset by default rather than defaulting to e.g. `low`: Step 15
    # ("Asset Criticality") is where real scoring gets built — defaulting
    # this now would imply false precision no code actually computed.
    criticality: Mapped[AssetCriticality | None] = mapped_column(
        Enum(AssetCriticality, name="asset_criticality"), nullable=True
    )
    # Free text, not an FK: no team/user-assignment concept exists yet in
    # this codebase. An FK can be added later without data loss if that
    # concept gets formalized.
    owner: Mapped[str | None] = mapped_column(String(255), nullable=True)
    tags: Mapped[list[str]] = mapped_column(ARRAY(String(100)), nullable=False, default=list)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    organization = relationship("Organization", back_populates="assets")
    parent_asset = relationship("Asset", remote_side="Asset.id", backref="child_assets")
    scans = relationship("Scan", back_populates="asset", cascade="all, delete-orphan")
    dns_records = relationship("DNSRecord", back_populates="asset", cascade="all, delete-orphan")
    ssl_info_entries = relationship("SSLInfo", back_populates="asset", cascade="all, delete-orphan")
    technologies = relationship("Technology", back_populates="asset", cascade="all, delete-orphan")
    services = relationship("Service", back_populates="asset", cascade="all, delete-orphan")
    certificates = relationship("Certificate", back_populates="asset", cascade="all, delete-orphan")
    # --- Step 8 (relationships/observations): the Asset Graph ---
    outgoing_relationships = relationship(
        "AssetRelationship",
        foreign_keys="AssetRelationship.source_asset_id",
        back_populates="source_asset",
        cascade="all, delete-orphan",
    )
    incoming_relationships = relationship(
        "AssetRelationship",
        foreign_keys="AssetRelationship.target_asset_id",
        back_populates="target_asset",
        cascade="all, delete-orphan",
    )
    observations = relationship("Observation", back_populates="asset", cascade="all, delete-orphan")
    # --- Step 9.1: Discovery ---
    # No cascade: DiscoveryRun is an audit-quality record (which provider
    # ran, when, with what outcome) that shouldn't vanish if this asset
    # is later removed — matches the FK's own ondelete choice.
    discovery_runs_as_seed = relationship("DiscoveryRun", back_populates="seed_asset")

    @validates("value")
    def _normalize_value(self, key: str, value: str) -> str:
        """Defense-in-depth normalization at the ORM layer. The authoritative
        per-type validation happens in app.core.validation before an Asset
        is ever constructed (see schemas.asset); this just guarantees the
        unique constraint can't be bypassed by case alone (Example.com vs
        example.com) if a row is ever created outside that path.

        Explicitly branches on self.asset_type and only lowercases for
        domain/subdomain: with Step 8's wider AssetType vocabulary, a
        blanket "lowercase anything without '://'" rule (the original
        approach) actively corrupts case-sensitive values -- an ASN like
        "AS15169" or a cloud_resource identifier like "AWS" would
        silently become "as15169"/"aws". If self.asset_type isn't set yet
        at validation time (attribute assignment order isn't guaranteed
        at construction), this simply skips the extra safety net rather
        than guessing — the schema-layer validation is authoritative
        regardless.
        """
        if self.asset_type in (AssetType.domain, AssetType.subdomain):
            return normalize_hostname(value)
        return value
