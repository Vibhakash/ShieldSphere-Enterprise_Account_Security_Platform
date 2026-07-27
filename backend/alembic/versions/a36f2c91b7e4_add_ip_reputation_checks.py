"""add ip reputation checks

Revision ID: a36f2c91b7e4
Revises: 75d062e7ef00
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "a36f2c91b7e4"
down_revision: Union[str, None] = "75d062e7ef00"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "ip_reputation_checks",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("ip_address", sa.String(length=45), nullable=False),
        sa.Column("overall_verdict", sa.String(length=50), nullable=False),
        sa.Column("virustotal_malicious", sa.Integer(), nullable=True),
        sa.Column("virustotal_suspicious", sa.Integer(), nullable=True),
        sa.Column("abuse_confidence_score", sa.Integer(), nullable=True),
        sa.Column("abuse_total_reports", sa.Integer(), nullable=True),
        sa.Column("raw_results", sa.JSON(), nullable=False),
        sa.Column("checked_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_ip_reputation_checks_checked_at"), "ip_reputation_checks", ["checked_at"])
    op.create_index(op.f("ix_ip_reputation_checks_ip_address"), "ip_reputation_checks", ["ip_address"])
    op.create_index(op.f("ix_ip_reputation_checks_user_id"), "ip_reputation_checks", ["user_id"])


def downgrade() -> None:
    op.drop_index(op.f("ix_ip_reputation_checks_user_id"), table_name="ip_reputation_checks")
    op.drop_index(op.f("ix_ip_reputation_checks_ip_address"), table_name="ip_reputation_checks")
    op.drop_index(op.f("ix_ip_reputation_checks_checked_at"), table_name="ip_reputation_checks")
    op.drop_table("ip_reputation_checks")
