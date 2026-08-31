"""step 9.5: http/web intelligence provider

Revision ID: 0010
Revises: 0009
Create Date: 2026-08-27

"""
from typing import Sequence, Union

from alembic import op

revision: str = "0010"
down_revision: Union[str, None] = "0009"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Additive: no column in this migration uses any of these new
    # values, so this is safe within a transaction (same convention as
    # every prior enum growth in this codebase).
    op.execute("ALTER TYPE change_type ADD VALUE IF NOT EXISTS 'http_observed'")
    op.execute("ALTER TYPE change_type ADD VALUE IF NOT EXISTS 'http_changed'")
    op.execute("ALTER TYPE discovery_result_outcome ADD VALUE IF NOT EXISTS 'failed'")


def downgrade() -> None:
    # Postgres has no ALTER TYPE ... DROP VALUE -- same accepted
    # limitation as every prior enum-value addition in this codebase.
    pass
