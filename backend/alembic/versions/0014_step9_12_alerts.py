"""step 9.12: alerting & change notifications

Revision ID: 0014
Revises: 0013
Create Date: 2026-08-28

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0014"
down_revision: Union[str, None] = "0013"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "alerts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "organization_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id"), nullable=False
        ),
        sa.Column(
            "asset_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=True
        ),
        sa.Column(
            "relationship_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("asset_relationships.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "discovery_run_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("discovery_runs.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "source_observation_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("observations.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "alert_type",
            sa.Enum(
                "new_externally_exposed_asset",
                "important_asset_disappeared",
                "important_asset_reappeared",
                "certificate_changed",
                "dns_infrastructure_changed",
                "http_security_posture_changed",
                "infrastructure_classification_changed",
                "high_priority_asset_detected",
                "authorization_disabled",
                name="alert_type",
            ),
            nullable=False,
        ),
        sa.Column(
            "priority",
            sa.Enum("informational", "low", "medium", "high", "critical", name="alert_priority"),
            nullable=False,
        ),
        sa.Column("title", sa.String(length=500), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("evidence", postgresql.JSONB(), nullable=True),
        sa.Column(
            "status",
            sa.Enum("open", "acknowledged", "resolved", name="alert_status"),
            nullable=False,
            server_default="open",
        ),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("occurrence_count", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("acknowledged_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolved_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_alerts_organization_id", "alerts", ["organization_id"])
    op.create_index("ix_alerts_organization_id_status", "alerts", ["organization_id", "status"])
    op.create_index("ix_alerts_asset_id", "alerts", ["asset_id"])
    # The real, PostgreSQL-enforced concurrency guarantee (Step
    # 9.12.16): at most one open-or-acknowledged alert may exist per
    # (organization_id, fingerprint). A resolved alert is excluded so
    # the same condition recurring after resolution can create a
    # genuinely new row.
    op.create_index(
        "uq_alerts_org_fingerprint_open",
        "alerts",
        ["organization_id", "fingerprint"],
        unique=True,
        postgresql_where=sa.text("status != 'resolved'"),
    )

    op.create_table(
        "alert_notifications",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "alert_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("channel", sa.Enum("email", name="notification_channel"), nullable=False),
        sa.Column(
            "status",
            sa.Enum("pending", "sending", "sent", "failed_transient", "failed_permanent", name="notification_status"),
            nullable=False,
            server_default="pending",
        ),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("delivered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_alert_notifications_alert_id", "alert_notifications", ["alert_id"])


def downgrade() -> None:
    op.drop_index("ix_alert_notifications_alert_id", table_name="alert_notifications")
    op.drop_table("alert_notifications")
    op.execute("DROP TYPE IF EXISTS notification_status")
    op.execute("DROP TYPE IF EXISTS notification_channel")

    op.drop_index("uq_alerts_org_fingerprint_open", table_name="alerts")
    op.drop_index("ix_alerts_asset_id", table_name="alerts")
    op.drop_index("ix_alerts_organization_id_status", table_name="alerts")
    op.drop_index("ix_alerts_organization_id", table_name="alerts")
    op.drop_table("alerts")
    op.execute("DROP TYPE IF EXISTS alert_status")
    op.execute("DROP TYPE IF EXISTS alert_priority")
    op.execute("DROP TYPE IF EXISTS alert_type")
