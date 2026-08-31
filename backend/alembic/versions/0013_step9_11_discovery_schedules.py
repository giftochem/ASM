"""step 9.11: continuous monitoring & discovery orchestration

Revision ID: 0013
Revises: 0012
Create Date: 2026-08-28

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0013"
down_revision: Union[str, None] = "0012"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # discovery_schedules references discovery_runs.id (last_run_id) --
    # safe to create now since discovery_runs already exists (migration
    # 0006). discovery_runs.schedule_id (added below, after this table
    # exists) closes the other direction of what is otherwise a mutual
    # reference between the two tables.
    op.create_table(
        "discovery_schedules",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "organization_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id"), nullable=False
        ),
        sa.Column("seed_asset_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("assets.id"), nullable=False),
        sa.Column("provider_name", sa.String(length=100), nullable=False),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("interval_hours", sa.Integer(), nullable=False),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "last_run_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("discovery_runs.id"), nullable=True
        ),
        sa.Column("claimed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("disabled_reason", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_discovery_schedules_organization_id", "discovery_schedules", ["organization_id"])
    op.create_index("ix_discovery_schedules_seed_asset_id", "discovery_schedules", ["seed_asset_id"])
    op.create_index("ix_discovery_schedules_next_run_at", "discovery_schedules", ["next_run_at"])

    op.add_column(
        "discovery_runs",
        sa.Column(
            "schedule_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("discovery_schedules.id"), nullable=True
        ),
    )


def downgrade() -> None:
    op.drop_column("discovery_runs", "schedule_id")

    op.drop_index("ix_discovery_schedules_next_run_at", table_name="discovery_schedules")
    op.drop_index("ix_discovery_schedules_seed_asset_id", table_name="discovery_schedules")
    op.drop_index("ix_discovery_schedules_organization_id", table_name="discovery_schedules")
    op.drop_table("discovery_schedules")
