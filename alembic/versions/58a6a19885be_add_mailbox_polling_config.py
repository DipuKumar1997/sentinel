"""add mailbox imap polling config and processed-message tracking

Revision ID: 58a6a19885be
Revises: 873fb9353f04
Create Date: 2026-09-06 10:00:00.000000

Hand-written for the same reason as the two prior migrations (see
c7bd488f4839's docstring): autogenerating against a SQLite shadow DB
reproduces UUID/NUMERIC diff noise across every existing column.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "58a6a19885be"
down_revision: Union[str, Sequence[str], None] = "873fb9353f04"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("mailboxes") as batch_op:
        batch_op.add_column(sa.Column("imap_host", sa.String(length=255), nullable=True))
        batch_op.add_column(sa.Column("imap_port", sa.Integer(), nullable=False, server_default="993"))
        batch_op.add_column(sa.Column("imap_use_ssl", sa.Boolean(), nullable=False, server_default=sa.true()))
        batch_op.add_column(sa.Column("imap_username", sa.String(length=255), nullable=True))
        batch_op.add_column(sa.Column("encrypted_password", sa.String(length=1024), nullable=True))
        batch_op.add_column(sa.Column("imap_folder", sa.String(length=255), nullable=False, server_default="INBOX"))
        batch_op.add_column(sa.Column("is_polling_enabled", sa.Boolean(), nullable=False, server_default=sa.false()))
        batch_op.add_column(sa.Column("poll_interval_seconds", sa.Integer(), nullable=False, server_default="120"))
        batch_op.add_column(sa.Column("last_polled_at", sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column("last_poll_status", sa.String(length=32), nullable=True))
        batch_op.add_column(sa.Column("last_poll_error", sa.Text(), nullable=True))
        batch_op.add_column(sa.Column("uid_validity", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("last_seen_uid", sa.Integer(), nullable=False, server_default="0"))
        batch_op.add_column(sa.Column("service_user_id", sa.Uuid(), nullable=True))
        batch_op.create_foreign_key(
            "fk_mailboxes_service_user_id", "users", ["service_user_id"], ["id"]
        )
        batch_op.alter_column("imap_port", server_default=None)
        batch_op.alter_column("imap_use_ssl", server_default=None)
        batch_op.alter_column("imap_folder", server_default=None)
        batch_op.alter_column("is_polling_enabled", server_default=None)
        batch_op.alter_column("poll_interval_seconds", server_default=None)
        batch_op.alter_column("last_seen_uid", server_default=None)

    op.create_table(
        "mailbox_processed_messages",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("mailbox_id", sa.Uuid(), sa.ForeignKey("mailboxes.id", ondelete="CASCADE"), nullable=False),
        sa.Column("imap_uid", sa.Integer(), nullable=False),
        sa.Column("message_id_header", sa.String(length=998), nullable=True),
        sa.Column("evidence_sha256", sa.String(length=64), nullable=True),
        sa.Column("case_id", sa.Uuid(), sa.ForeignKey("cases.id"), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="created"),
        sa.Column("detail", sa.Text(), nullable=True),
    )
    op.create_index(
        "ix_mailbox_processed_messages_mailbox_id", "mailbox_processed_messages", ["mailbox_id"]
    )
    op.create_index(
        "ix_mailbox_processed_messages_imap_uid", "mailbox_processed_messages", ["imap_uid"]
    )


def downgrade() -> None:
    op.drop_index("ix_mailbox_processed_messages_imap_uid", table_name="mailbox_processed_messages")
    op.drop_index("ix_mailbox_processed_messages_mailbox_id", table_name="mailbox_processed_messages")
    op.drop_table("mailbox_processed_messages")

    with op.batch_alter_table("mailboxes") as batch_op:
        batch_op.drop_constraint("fk_mailboxes_service_user_id", type_="foreignkey")
        batch_op.drop_column("service_user_id")
        batch_op.drop_column("last_seen_uid")
        batch_op.drop_column("uid_validity")
        batch_op.drop_column("last_poll_error")
        batch_op.drop_column("last_poll_status")
        batch_op.drop_column("last_polled_at")
        batch_op.drop_column("poll_interval_seconds")
        batch_op.drop_column("is_polling_enabled")
        batch_op.drop_column("imap_folder")
        batch_op.drop_column("encrypted_password")
        batch_op.drop_column("imap_username")
        batch_op.drop_column("imap_use_ssl")
        batch_op.drop_column("imap_port")
        batch_op.drop_column("imap_host")
