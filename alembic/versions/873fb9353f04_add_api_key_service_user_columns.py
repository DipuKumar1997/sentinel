"""add service_user_id and created_by_user_id to api_keys

Revision ID: 873fb9353f04
Revises: c7bd488f4839
Create Date: 2026-09-06 02:50:00.000000

Hand-written for the same reason as c7bd488f4839 (see that migration's
docstring): autogenerating a second time against a SQLite shadow DB
reproduces UUID/NUMERIC diff noise across every existing column. Only
the two genuinely new columns are included here.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "873fb9353f04"
down_revision: Union[str, Sequence[str], None] = "c7bd488f4839"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("api_keys") as batch_op:
        batch_op.add_column(sa.Column("service_user_id", sa.Uuid(), nullable=True))
        batch_op.add_column(sa.Column("created_by_user_id", sa.Uuid(), nullable=True))
        batch_op.create_foreign_key(
            "fk_api_keys_service_user_id", "users", ["service_user_id"], ["id"]
        )
        batch_op.create_foreign_key(
            "fk_api_keys_created_by_user_id", "users", ["created_by_user_id"], ["id"]
        )


def downgrade() -> None:
    with op.batch_alter_table("api_keys") as batch_op:
        batch_op.drop_constraint("fk_api_keys_created_by_user_id", type_="foreignkey")
        batch_op.drop_constraint("fk_api_keys_service_user_id", type_="foreignkey")
        batch_op.drop_column("created_by_user_id")
        batch_op.drop_column("service_user_id")
