"""step 9.1: discovery intelligence foundation

Revision ID: 0006
Revises: 0005
Create Date: 2026-08-26

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0006"
down_revision: Union[str, None] = "0005"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        "CREATE TYPE discovery_run_status AS ENUM ("
        "'queued', 'running', 'completed', 'failed', 'cancelled'"
        ")"
    )
    op.execute("CREATE TYPE discovery_result_outcome AS ENUM ('created', 'refreshed', 'rejected')")

    op.create_table(
        "discovery_runs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "organization_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id"),
            nullable=False,
        ),
        # No ondelete=CASCADE: an audit-quality record that shouldn't
        # vanish if the seed asset is later removed -- matches
        # audit_logs' FK style, not asset_relationships'/observations'.
        sa.Column(
            "seed_asset_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("assets.id"), nullable=False
        ),
        sa.Column(
            "initiated_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=False
        ),
        sa.Column("provider_name", sa.String(length=100), nullable=False),
        sa.Column(
            "status",
            postgresql.ENUM(name="discovery_run_status", create_type=False),
            nullable=False,
            server_default="queued",
        ),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_discovery_runs_organization_id", "discovery_runs", ["organization_id"])
    op.create_index("ix_discovery_runs_seed_asset_id", "discovery_runs", ["seed_asset_id"])

    op.create_table(
        "discovery_results",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "discovery_run_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("discovery_runs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "candidate_asset_type",
            postgresql.ENUM(name="asset_type", create_type=False),
            nullable=False,
        ),
        sa.Column("candidate_value", sa.String(length=255), nullable=False),
        sa.Column(
            "relationship_type",
            postgresql.ENUM(name="relationship_type", create_type=False),
            nullable=True,
        ),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("evidence", postgresql.JSONB(), nullable=True),
        sa.Column(
            "outcome",
            postgresql.ENUM(name="discovery_result_outcome", create_type=False),
            nullable=False,
        ),
        sa.Column(
            "resulting_asset_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("assets.id"), nullable=True
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_discovery_results_discovery_run_id", "discovery_results", ["discovery_run_id"])


def downgrade() -> None:
    op.drop_index("ix_discovery_results_discovery_run_id", table_name="discovery_results")
    op.drop_table("discovery_results")

    op.drop_index("ix_discovery_runs_seed_asset_id", table_name="discovery_runs")
    op.drop_index("ix_discovery_runs_organization_id", table_name="discovery_runs")
    op.drop_table("discovery_runs")

    op.execute("DROP TYPE discovery_result_outcome")
    op.execute("DROP TYPE discovery_run_status")
