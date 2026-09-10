"""add smtp send-back config to mailboxes

Revision ID: 78d4f2743bf4
Revises: 678b0af40172
Create Date: 2026-09-08 14:00:00.000000

Hand-written for the same reason as the four prior migrations (see
c7bd488f4839's docstring): autogenerating against a SQLite shadow DB
reproduces UUID/NUMERIC diff noise across every existing column.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "78d4f2743bf4"
down_revision: Union[str, Sequence[str], None] = "678b0af40172"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("mailboxes") as batch_op:
        batch_op.add_column(sa.Column("smtp_host", sa.String(length=255), nullable=True))
        batch_op.add_column(sa.Column("smtp_port", sa.Integer(), nullable=False, server_default="587"))
        batch_op.add_column(sa.Column("smtp_use_tls", sa.Boolean(), nullable=False, server_default=sa.true()))
        batch_op.add_column(sa.Column("notify_reporter", sa.Boolean(), nullable=False, server_default=sa.true()))
        batch_op.alter_column("smtp_port", server_default=None)
        batch_op.alter_column("smtp_use_tls", server_default=None)
        batch_op.alter_column("notify_reporter", server_default=None)


def downgrade() -> None:
    with op.batch_alter_table("mailboxes") as batch_op:
        batch_op.drop_column("notify_reporter")
        batch_op.drop_column("smtp_use_tls")
        batch_op.drop_column("smtp_port")
        batch_op.drop_column("smtp_host")
