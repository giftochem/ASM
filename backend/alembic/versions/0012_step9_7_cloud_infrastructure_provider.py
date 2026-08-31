"""step 9.7: cloud/infrastructure intelligence provider

Revision ID: 0012
Revises: 0011
Create Date: 2026-08-27

"""
from typing import Sequence, Union

from alembic import op

revision: str = "0012"
down_revision: Union[str, None] = "0011"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Additive: no column in this migration uses either new value, so
    # this is safe within a transaction (same convention as every prior
    # enum growth in this codebase). No new RelationshipType, no new
    # DiscoveryResultOutcome, no new table -- see the Step 9.7
    # completion report for why (cloud/infrastructure attribution is
    # recorded as Observation evidence, not a new Asset/relationship).
    op.execute("ALTER TYPE change_type ADD VALUE IF NOT EXISTS 'infrastructure_observed'")
    op.execute("ALTER TYPE change_type ADD VALUE IF NOT EXISTS 'infrastructure_changed'")


def downgrade() -> None:
    # Postgres has no ALTER TYPE ... DROP VALUE -- same accepted
    # limitation as every prior enum-value addition in this codebase.
    pass
