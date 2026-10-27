"""SID to user map.

Revision ID: 0002_sid_users
Revises: 0001_initial
Create Date: 2026-10-27

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002_sid_users"
down_revision: str | None = "0001_initial"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "sid_users",
        sa.Column("sid", sa.String(), primary_key=True),
        sa.Column("user_name", sa.String(), nullable=False),
        sa.Column("last_seen", sa.String(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("sid_users")
