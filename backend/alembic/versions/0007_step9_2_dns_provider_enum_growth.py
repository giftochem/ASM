"""step 9.2: dns provider enum growth

Revision ID: 0007
Revises: 0006
Create Date: 2026-08-26

"""
from typing import Sequence, Union

from alembic import op

revision: str = "0007"
down_revision: Union[str, None] = "0006"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Both additive: neither column that uses these enums is touched in
    # this migration, so this is safe within a transaction (same
    # convention as scan_status gaining 'cancelled' in 0002).
    op.execute("ALTER TYPE discovery_result_outcome ADD VALUE IF NOT EXISTS 'observed'")
    op.execute("ALTER TYPE change_type ADD VALUE IF NOT EXISTS 'dns_records_observed'")


def downgrade() -> None:
    # Postgres has no ALTER TYPE ... DROP VALUE -- same accepted
    # limitation as every prior enum-value addition in this codebase
    # (see 0002's downgrade note on scan_status gaining 'cancelled').
    pass
