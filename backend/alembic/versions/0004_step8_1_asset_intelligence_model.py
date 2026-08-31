"""step 8.1: asset intelligence domain model

Revision ID: 0004
Revises: 0003
Create Date: 2026-08-21

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0004"
down_revision: Union[str, None] = "0003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # New enum types, created explicitly since each is reused across
    # multiple tables/columns in this same migration (create_type=False
    # on every column reference below, same convention as 0002/0003).
    op.execute("CREATE TYPE lifecycle_status AS ENUM ('first_seen', 'active', 'stale', 'disappeared')")
    op.execute("CREATE TYPE asset_source AS ENUM ('manual', 'discovery')")
    op.execute(
        "CREATE TYPE asset_environment AS ENUM ('production', 'staging', 'development', 'test', 'unknown')"
    )
    op.execute("CREATE TYPE asset_criticality AS ENUM ('low', 'medium', 'high', 'critical')")

    # assets: Asset Intelligence fields. Every NOT NULL column gets a
    # server_default so existing rows (including live dev-DB data)
    # backfill in the same statement — same pattern as 0002 adding
    # exposure/exploitability to findings.
    op.add_column(
        "assets",
        sa.Column(
            "status",
            postgresql.ENUM(name="lifecycle_status", create_type=False),
            nullable=False,
            server_default="active",
        ),
    )
    op.add_column(
        "assets",
        sa.Column(
            "source",
            postgresql.ENUM(name="asset_source", create_type=False),
            nullable=False,
            server_default="manual",
        ),
    )
    op.add_column("assets", sa.Column("confidence", sa.Float(), nullable=False, server_default="1.0"))
    op.add_column(
        "assets",
        sa.Column("environment", postgresql.ENUM(name="asset_environment", create_type=False), nullable=True),
    )
    op.add_column(
        "assets",
        sa.Column("criticality", postgresql.ENUM(name="asset_criticality", create_type=False), nullable=True),
    )
    op.add_column("assets", sa.Column("owner", sa.String(length=255), nullable=True))
    op.add_column(
        "assets",
        sa.Column(
            "tags",
            postgresql.ARRAY(sa.String(length=100)),
            nullable=False,
            server_default="{}",
        ),
    )
    op.add_column(
        "assets",
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.add_column(
        "assets",
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )

    # services: deduped current-state service inventory per asset.
    op.create_table(
        "services",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "asset_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("assets.id"), nullable=False
        ),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("protocol", sa.String(length=10), nullable=False, server_default="tcp"),
        sa.Column("service_name", sa.String(length=100), nullable=True),
        sa.Column("product", sa.String(length=255), nullable=True),
        sa.Column("version", sa.String(length=100), nullable=True),
        sa.Column("banner", sa.Text(), nullable=True),
        sa.Column(
            "status",
            postgresql.ENUM(name="lifecycle_status", create_type=False),
            nullable=False,
            server_default="active",
        ),
        sa.Column(
            "source",
            postgresql.ENUM(name="asset_source", create_type=False),
            nullable=False,
            server_default="manual",
        ),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="1.0"),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("asset_id", "port", "protocol", name="uq_service_asset_port_protocol"),
    )

    # certificates: deduped current-state certificate per asset+hostname+port.
    op.create_table(
        "certificates",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "asset_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("assets.id"), nullable=False
        ),
        sa.Column("hostname", sa.String(length=255), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False, server_default="443"),
        sa.Column("issuer", sa.String(length=500), nullable=True),
        sa.Column("subject", sa.String(length=500), nullable=True),
        sa.Column("valid_from", sa.DateTime(timezone=True), nullable=True),
        sa.Column("valid_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("serial_number", sa.String(length=100), nullable=True),
        sa.Column("fingerprint_sha256", sa.String(length=64), nullable=True),
        sa.Column("signature_algorithm", sa.String(length=100), nullable=True),
        sa.Column("protocol_version", sa.String(length=20), nullable=True),
        sa.Column("cipher_suite", sa.String(length=100), nullable=True),
        sa.Column("subject_alt_names", postgresql.ARRAY(sa.String(length=255)), nullable=True),
        sa.Column("is_expired", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("is_self_signed", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column(
            "status",
            postgresql.ENUM(name="lifecycle_status", create_type=False),
            nullable=False,
            server_default="active",
        ),
        sa.Column(
            "source",
            postgresql.ENUM(name="asset_source", create_type=False),
            nullable=False,
            server_default="manual",
        ),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="1.0"),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("asset_id", "hostname", "port", name="uq_certificate_asset_hostname_port"),
    )


def downgrade() -> None:
    op.drop_table("certificates")
    op.drop_table("services")

    op.drop_column("assets", "last_seen")
    op.drop_column("assets", "first_seen")
    op.drop_column("assets", "tags")
    op.drop_column("assets", "owner")
    op.drop_column("assets", "criticality")
    op.drop_column("assets", "environment")
    op.drop_column("assets", "confidence")
    op.drop_column("assets", "source")
    op.drop_column("assets", "status")

    op.execute("DROP TYPE asset_criticality")
    op.execute("DROP TYPE asset_environment")
    op.execute("DROP TYPE asset_source")
    op.execute("DROP TYPE lifecycle_status")
