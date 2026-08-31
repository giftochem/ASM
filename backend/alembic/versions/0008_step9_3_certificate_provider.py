"""step 9.3: certificate provider

Revision ID: 0008
Revises: 0007
Create Date: 2026-08-26

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0008"
down_revision: Union[str, None] = "0007"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # All nullable -- existing certificates rows (Step 8.1) had no data
    # for these, and there's nothing sensible to backfill.
    op.add_column("certificates", sa.Column("certificate_version", sa.String(length=10), nullable=True))
    op.add_column("certificates", sa.Column("public_key_algorithm", sa.String(length=50), nullable=True))
    op.add_column("certificates", sa.Column("public_key_size", sa.Integer(), nullable=True))
    op.create_index("ix_certificates_fingerprint_sha256", "certificates", ["fingerprint_sha256"])

    # Also additive: no column uses these new enum values in this same
    # migration, so this is safe within a transaction (same convention
    # as every prior enum growth in this codebase).
    op.execute("ALTER TYPE change_type ADD VALUE IF NOT EXISTS 'certificate_observed'")
    op.execute("ALTER TYPE change_type ADD VALUE IF NOT EXISTS 'certificate_changed'")
    op.execute("ALTER TYPE discovery_result_outcome ADD VALUE IF NOT EXISTS 'unchanged'")


def downgrade() -> None:
    op.drop_index("ix_certificates_fingerprint_sha256", table_name="certificates")
    op.drop_column("certificates", "public_key_size")
    op.drop_column("certificates", "public_key_algorithm")
    op.drop_column("certificates", "certificate_version")
    # Postgres has no ALTER TYPE ... DROP VALUE -- same accepted
    # limitation as every prior enum-value addition in this codebase.
