"""add passkeys and notification integrations

Revision ID: e719f8c420b1
Revises: c82e1f604d29
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "e719f8c420b1"
down_revision: Union[str, None] = "c82e1f604d29"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "passkey_credentials",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("credential_id", sa.Text(), nullable=False),
        sa.Column("public_key", sa.LargeBinary(), nullable=False),
        sa.Column("sign_count", sa.Integer(), nullable=False),
        sa.Column("transports", sa.JSON(), nullable=True),
        sa.Column("device_type", sa.String(length=30), nullable=True),
        sa.Column("backed_up", sa.Boolean(), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("credential_id"),
    )
    op.create_index(op.f("ix_passkey_credentials_user_id"), "passkey_credentials", ["user_id"])

    op.create_table(
        "notification_integrations",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("integration_type", sa.String(length=20), nullable=False),
        sa.Column("destination", sa.Text(), nullable=False),
        sa.Column("signing_secret_encrypted", sa.Text(), nullable=True),
        sa.Column("minimum_severity", sa.String(length=20), nullable=False),
        sa.Column("include_simulations", sa.Boolean(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_delivery_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_delivery_status", sa.String(length=20), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_notification_integrations_user_id"), "notification_integrations", ["user_id"])

    op.create_table(
        "integration_deliveries",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("integration_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("alert_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("event_type", sa.String(length=80), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("response_code", sa.Integer(), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("attempted_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["alert_id"], ["alerts.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["integration_id"], ["notification_integrations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_integration_deliveries_alert_id"), "integration_deliveries", ["alert_id"])
    op.create_index(op.f("ix_integration_deliveries_integration_id"), "integration_deliveries", ["integration_id"])


def downgrade() -> None:
    op.drop_index(op.f("ix_integration_deliveries_integration_id"), table_name="integration_deliveries")
    op.drop_index(op.f("ix_integration_deliveries_alert_id"), table_name="integration_deliveries")
    op.drop_table("integration_deliveries")
    op.drop_index(op.f("ix_notification_integrations_user_id"), table_name="notification_integrations")
    op.drop_table("notification_integrations")
    op.drop_index(op.f("ix_passkey_credentials_user_id"), table_name="passkey_credentials")
    op.drop_table("passkey_credentials")
