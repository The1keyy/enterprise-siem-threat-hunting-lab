"""Correlation checkpoint, ingested alerts, and incident explanation columns.

Revision ID: 0003_correlation_state
Revises: 0002_sid_users
Create Date: 2026-10-27

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003_correlation_state"
down_revision: str | None = "0002_sid_users"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "incidents",
        sa.Column("link_reasons", sa.JSON(), nullable=False, server_default="[]"),
    )
    op.add_column(
        "incidents",
        sa.Column("multiplier_hosts", sa.JSON(), nullable=False, server_default="[]"),
    )
    op.add_column(
        "incidents",
        sa.Column("spray_findings", sa.JSON(), nullable=False, server_default="[]"),
    )
    op.add_column(
        "incidents",
        sa.Column("checklist", sa.JSON(), nullable=False, server_default="[]"),
    )
    op.add_column("incidents", sa.Column("engine", sa.JSON(), nullable=True))
    op.add_column(
        "risk_events",
        sa.Column("counted", sa.Boolean(), nullable=False, server_default=sa.true()),
    )
    op.add_column(
        "risk_events",
        sa.Column("reason", sa.String(), nullable=False, server_default="counted"),
    )
    op.create_table(
        "ingested_alerts",
        sa.Column("alert_id", sa.String(), primary_key=True),
        sa.Column("incident_id", sa.String(), nullable=False),
        sa.Column("sort_time", sa.String(), nullable=False),
        sa.Column("document", sa.JSON(), nullable=False),
    )
    op.create_table(
        "correlation_state",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("checkpoint_time", sa.String(), nullable=True),
        sa.Column("checkpoint_id", sa.String(), nullable=True),
        sa.Column("last_run_at", sa.String(), nullable=True),
        sa.Column("alerts_processed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_error", sa.String(), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("correlation_state")
    op.drop_table("ingested_alerts")
    op.drop_column("risk_events", "reason")
    op.drop_column("risk_events", "counted")
    op.drop_column("incidents", "engine")
    op.drop_column("incidents", "checklist")
    op.drop_column("incidents", "spray_findings")
    op.drop_column("incidents", "multiplier_hosts")
    op.drop_column("incidents", "link_reasons")
