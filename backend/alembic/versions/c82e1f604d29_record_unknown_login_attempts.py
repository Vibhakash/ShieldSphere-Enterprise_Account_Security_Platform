"""record unknown login attempts

Revision ID: c82e1f604d29
Revises: a36f2c91b7e4
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "c82e1f604d29"
down_revision: Union[str, None] = "a36f2c91b7e4"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.drop_constraint("fk_login_history_user_id_users", "login_history", type_="foreignkey")
    op.alter_column("login_history", "user_id", existing_type=sa.UUID(), nullable=True)
    op.create_foreign_key(
        op.f("fk_login_history_user_id_users"),
        "login_history", "users", ["user_id"], ["id"], ondelete="SET NULL",
    )
    op.add_column("login_history", sa.Column("attempted_identifier_hash", sa.String(length=64), nullable=True))
    op.create_index(
        op.f("ix_login_history_attempted_identifier_hash"),
        "login_history", ["attempted_identifier_hash"], unique=False,
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_login_history_attempted_identifier_hash"), table_name="login_history")
    op.drop_column("login_history", "attempted_identifier_hash")
    op.execute("DELETE FROM login_history WHERE user_id IS NULL")
    op.drop_constraint("fk_login_history_user_id_users", "login_history", type_="foreignkey")
    op.alter_column("login_history", "user_id", existing_type=sa.UUID(), nullable=False)
    op.create_foreign_key(
        op.f("fk_login_history_user_id_users"),
        "login_history", "users", ["user_id"], ["id"], ondelete="CASCADE",
    )
