"""step 8: asset relationships and observations

Revision ID: 0005
Revises: 0004
Create Date: 2026-08-21

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0005"
down_revision: Union[str, None] = "0004"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_NEW_ASSET_TYPES = [
    "asn",
    "service",
    "http_endpoint",
    "tls_certificate",
    "api",
    "cloud_resource",
    "repository",
    "web3_contract",
    "web3_program",
    "web3_token",
    "web3_wallet",
    "rpc_endpoint",
]


def upgrade() -> None:
    # Each ADD VALUE is its own statement/transaction-safe, same as
    # scan_status gaining 'cancelled' in 0002 -- safe because no column
    # in this migration uses any of these new values yet.
    for value in _NEW_ASSET_TYPES:
        op.execute(f"ALTER TYPE asset_type ADD VALUE IF NOT EXISTS '{value}'")

    op.execute(
        "CREATE TYPE relationship_type AS ENUM ("
        "'owns', 'resolves_to', 'hosts', 'exposes', 'uses', 'belongs_to', "
        "'interacts_with', 'deployed_on', 'served_by', 'related_to'"
        ")"
    )
    op.execute(
        "CREATE TYPE change_type AS ENUM ("
        "'asset_created', 'asset_updated', 'asset_status_changed', "
        "'relationship_created', 'relationship_updated', 'relationship_removed'"
        ")"
    )

    op.create_table(
        "asset_relationships",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "source_asset_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("assets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "target_asset_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("assets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "relationship_type",
            postgresql.ENUM(name="relationship_type", create_type=False),
            nullable=False,
        ),
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
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint(
            "source_asset_id", "target_asset_id", "relationship_type",
            name="uq_relationship_source_target_type",
        ),
        sa.CheckConstraint("source_asset_id != target_asset_id", name="ck_relationship_no_self_reference"),
    )
    op.create_index(
        "ix_asset_relationships_target_asset_id", "asset_relationships", ["target_asset_id"]
    )

    op.create_table(
        "observations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "asset_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column(
            "change_type",
            postgresql.ENUM(name="change_type", create_type=False),
            nullable=False,
        ),
        sa.Column("field_name", sa.String(length=100), nullable=True),
        sa.Column("previous_value", sa.Text(), nullable=True),
        sa.Column("current_value", sa.Text(), nullable=True),
        sa.Column(
            "source",
            postgresql.ENUM(name="asset_source", create_type=False),
            nullable=False,
            server_default="manual",
        ),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="1.0"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index(
        "ix_observations_asset_id_observed_at", "observations", ["asset_id", "observed_at"]
    )


def downgrade() -> None:
    op.drop_index("ix_observations_asset_id_observed_at", table_name="observations")
    op.drop_table("observations")

    op.drop_index("ix_asset_relationships_target_asset_id", table_name="asset_relationships")
    op.drop_table("asset_relationships")

    op.execute("DROP TYPE change_type")
    op.execute("DROP TYPE relationship_type")

    # Not removing the 12 added asset_type values: Postgres has no ALTER
    # TYPE ... DROP VALUE, same accepted limitation as scan_status's
    # 'cancelled' in migration 0002's downgrade.
