"""step 9.6: asn/ip network intelligence provider

Revision ID: 0011
Revises: 0010
Create Date: 2026-08-27

"""
from typing import Sequence, Union

from alembic import op

revision: str = "0011"
down_revision: Union[str, None] = "0010"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Additive: no column in this migration uses any of these new
    # values, so this is safe within a transaction (same convention as
    # every prior enum growth in this codebase).
    op.execute("ALTER TYPE relationship_type ADD VALUE IF NOT EXISTS 'announced_by'")
    op.execute("ALTER TYPE change_type ADD VALUE IF NOT EXISTS 'network_observed'")
    op.execute("ALTER TYPE change_type ADD VALUE IF NOT EXISTS 'network_changed'")


def downgrade() -> None:
    # Postgres has no ALTER TYPE ... DROP VALUE -- same accepted
    # limitation as every prior enum-value addition in this codebase.
    pass
