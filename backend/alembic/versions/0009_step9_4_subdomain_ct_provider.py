"""step 9.4: subdomain discovery provider (certificate transparency)

Revision ID: 0009
Revises: 0008
Create Date: 2026-08-27

"""
from typing import Sequence, Union

from alembic import op

revision: str = "0009"
down_revision: Union[str, None] = "0008"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Additive: no column in this migration uses this new value, so this
    # is safe within a transaction (same convention as every prior enum
    # growth in this codebase).
    op.execute("ALTER TYPE change_type ADD VALUE IF NOT EXISTS 'certificate_transparency_observed'")


def downgrade() -> None:
    # Postgres has no ALTER TYPE ... DROP VALUE -- same accepted
    # limitation as every prior enum-value addition in this codebase.
    pass
