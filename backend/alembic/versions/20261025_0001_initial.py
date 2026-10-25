"""Initial analyst tables.

Revision ID: 0001_initial
Revises:
Create Date: 2026-10-25

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0001_initial"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "incidents",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("title", sa.String(), nullable=False),
        sa.Column("severity", sa.String(), nullable=False),
        sa.Column("risk_score", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("owner", sa.String(), nullable=False),
        sa.Column("users", sa.JSON(), nullable=False),
        sa.Column("hosts", sa.JSON(), nullable=False),
        sa.Column("mitre", sa.JSON(), nullable=False),
        sa.Column("first_seen", sa.String(), nullable=False),
        sa.Column("last_seen", sa.String(), nullable=False),
        sa.Column("demo", sa.Boolean(), nullable=False),
        sa.Column("entities", sa.JSON(), nullable=False),
        sa.Column("risk", sa.JSON(), nullable=False),
        sa.Column("disposition", sa.String(), nullable=False),
        sa.Column("summary", sa.String(), nullable=False),
        sa.Column("recommended_containment", sa.JSON(), nullable=False),
    )
    op.create_table(
        "incident_events",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("incident_id", sa.String(), sa.ForeignKey("incidents.id"), nullable=False),
        sa.Column("time", sa.String(), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
    )
    op.create_table(
        "notes",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("incident_id", sa.String(), sa.ForeignKey("incidents.id"), nullable=False),
        sa.Column("author", sa.String(), nullable=False),
        sa.Column("time", sa.String(), nullable=False),
        sa.Column("text", sa.String(), nullable=False),
    )
    op.create_table(
        "risk_events",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("incident_id", sa.String(), sa.ForeignKey("incidents.id"), nullable=False),
        sa.Column("event", sa.String(), nullable=False),
        sa.Column("rule_id", sa.String(), nullable=False),
        sa.Column("points", sa.Integer(), nullable=False),
    )
    op.create_table(
        "saved_hunts",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("hypothesis", sa.String(), nullable=False),
        sa.Column("data_source", sa.String(), nullable=False),
        sa.Column("query", sa.String(), nullable=False),
        sa.Column("expected_behavior", sa.String(), nullable=False),
        sa.Column("suspicious_behavior", sa.String(), nullable=False),
        sa.Column("mitre", sa.JSON(), nullable=False),
        sa.Column("investigation_guidance", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("demo", sa.Boolean(), nullable=False),
    )
    op.create_table(
        "audit_log",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("time", sa.String(), nullable=False),
        sa.Column("actor", sa.String(), nullable=False),
        sa.Column("action", sa.String(), nullable=False),
        sa.Column("target", sa.String(), nullable=False),
        sa.Column("details", sa.JSON(), nullable=False),
        sa.Column("dry_run", sa.Boolean(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("audit_log")
    op.drop_table("saved_hunts")
    op.drop_table("risk_events")
    op.drop_table("notes")
    op.drop_table("incident_events")
    op.drop_table("incidents")
