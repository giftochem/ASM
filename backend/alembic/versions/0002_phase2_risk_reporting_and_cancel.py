"""phase 2: risk scoring, reporting status, scan cancellation

Revision ID: 0002
Revises: 0001
Create Date: 2026-08-10

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0002"
down_revision: Union[str, None] = "0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # New enum types, created explicitly (create_type=False on the column
    # defs below so SQLAlchemy doesn't try to create them a second time).
    op.execute("CREATE TYPE risk_severity_band AS ENUM ('minimal', 'low', 'medium', 'high', 'critical')")
    op.execute("CREATE TYPE report_status AS ENUM ('pending', 'generating', 'completed', 'failed')")

    # Safe within a transaction on Postgres 12+ as long as the new value
    # isn't used in the same transaction, which it isn't here.
    op.execute("ALTER TYPE scan_status ADD VALUE IF NOT EXISTS 'cancelled'")

    # findings: risk_engine inputs. confidence already existed as nullable
    # in 0001 even though the application always supplied it — tighten to
    # match reality, backfilling any (currently nonexistent, but handle
    # correctness anyway) NULLs before the NOT NULL constraint is added.
    op.add_column(
        "findings",
        sa.Column("exposure", sa.Float(), nullable=False, server_default="1.0"),
    )
    op.add_column(
        "findings",
        sa.Column("exploitability", sa.Float(), nullable=False, server_default="0.5"),
    )
    op.execute("UPDATE findings SET confidence = 1.0 WHERE confidence IS NULL")
    op.alter_column("findings", "confidence", existing_type=sa.Float(), nullable=False, server_default="1.0")

    # scans: aggregate risk_engine output, computed by scan_executor.
    op.add_column("scans", sa.Column("risk_score", sa.Float(), nullable=True))
    op.add_column(
        "scans",
        sa.Column(
            "risk_severity_band",
            postgresql.ENUM(name="risk_severity_band", create_type=False),
            nullable=True,
        ),
    )

    # reports: generation lifecycle tracking.
    op.add_column(
        "reports",
        sa.Column(
            "status",
            postgresql.ENUM(name="report_status", create_type=False),
            nullable=False,
            server_default="pending",
        ),
    )
    op.add_column("reports", sa.Column("error_message", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("reports", "error_message")
    op.drop_column("reports", "status")

    op.drop_column("scans", "risk_severity_band")
    op.drop_column("scans", "risk_score")

    op.alter_column("findings", "confidence", existing_type=sa.Float(), nullable=True, server_default=None)
    op.drop_column("findings", "exploitability")
    op.drop_column("findings", "exposure")

    op.execute("DROP TYPE report_status")
    op.execute("DROP TYPE risk_severity_band")

    # Not removing 'cancelled' from scan_status: Postgres has no ALTER
    # TYPE ... DROP VALUE. Removing it requires rebuilding the enum type
    # (rename, recreate without the value, migrate the column, drop the
    # old type) — not worth the risk/complexity for a downgrade path in a
    # pre-release schema. The unused value is harmless if left in place.
