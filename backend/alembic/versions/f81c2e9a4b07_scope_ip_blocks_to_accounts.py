"""scope IP blocks to accounts and synchronize expiration

Revision ID: f81c2e9a4b07
Revises: e719f8c420b1
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "f81c2e9a4b07"
down_revision: Union[str, None] = "e719f8c420b1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "ip_blocklist",
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.create_foreign_key(
        "fk_ip_blocklist_user_id_users",
        "ip_blocklist",
        "users",
        ["user_id"],
        ["id"],
        ondelete="CASCADE",
    )
    op.execute(
        """
        UPDATE ip_blocklist
        SET user_id = blocked_by_user_id
        WHERE blocked_by_user_id IS NOT NULL
        """
    )
    op.execute(
        """
        UPDATE ip_blocklist
        SET expires_at = blocked_at + INTERVAL '24 hours'
        WHERE auto_blocked = TRUE AND expires_at IS NULL
        """
    )
    op.drop_index(op.f("ix_ip_blocklist_ip_address"), table_name="ip_blocklist")
    op.create_index(
        op.f("ix_ip_blocklist_ip_address"),
        "ip_blocklist",
        ["ip_address"],
        unique=False,
    )
    op.create_index(
        op.f("ix_ip_blocklist_user_id"),
        "ip_blocklist",
        ["user_id"],
        unique=False,
    )
    op.create_index(
        "uq_ip_blocklist_account_ip",
        "ip_blocklist",
        ["user_id", "ip_address"],
        unique=True,
        postgresql_where=sa.text("user_id IS NOT NULL"),
    )
    op.create_index(
        "uq_ip_blocklist_global_ip",
        "ip_blocklist",
        ["ip_address"],
        unique=True,
        postgresql_where=sa.text("user_id IS NULL"),
    )


def downgrade() -> None:
    op.drop_index("uq_ip_blocklist_global_ip", table_name="ip_blocklist")
    op.drop_index("uq_ip_blocklist_account_ip", table_name="ip_blocklist")
    op.drop_index(op.f("ix_ip_blocklist_user_id"), table_name="ip_blocklist")
    op.drop_index(op.f("ix_ip_blocklist_ip_address"), table_name="ip_blocklist")
    op.create_index(
        op.f("ix_ip_blocklist_ip_address"),
        "ip_blocklist",
        ["ip_address"],
        unique=True,
    )
    op.drop_constraint(
        "fk_ip_blocklist_user_id_users",
        "ip_blocklist",
        type_="foreignkey",
    )
    op.drop_column("ip_blocklist", "user_id")
