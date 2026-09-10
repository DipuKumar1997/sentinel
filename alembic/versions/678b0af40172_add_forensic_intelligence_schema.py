"""add forensic intelligence: origin resolution, ip intelligence, dns
observations, blockchain anchors

Revision ID: 678b0af40172
Revises: 58a6a19885be
Create Date: 2026-09-08 09:00:00.000000

Hand-written for the same reason as the three prior migrations (see
c7bd488f4839's docstring): autogenerating against a SQLite shadow DB
reproduces UUID/NUMERIC diff noise across every existing column.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "678b0af40172"
down_revision: Union[str, Sequence[str], None] = "58a6a19885be"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # --- Earliest Reliable Origin fields on email_messages ---
    with op.batch_alter_table("email_messages") as batch_op:
        batch_op.add_column(sa.Column("origin_ip", sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column("origin_confidence", sa.Float(), nullable=True))
        batch_op.add_column(sa.Column("origin_reasoning", sa.Text(), nullable=True))
        batch_op.add_column(sa.Column("origin_determined", sa.Boolean(), nullable=False, server_default=sa.false()))
        batch_op.alter_column("origin_determined", server_default=None)

    # --- IP intelligence extensions on ips ---
    with op.batch_alter_table("ips") as batch_op:
        batch_op.add_column(sa.Column("geolocation_source", sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column("ptr_hostname", sa.String(length=255), nullable=True))
        batch_op.add_column(sa.Column("hosting_classification", sa.String(length=32), nullable=True))
        batch_op.add_column(sa.Column("hosting_classification_source", sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column("is_vpn_or_proxy_suspected", sa.Boolean(), nullable=True))
        batch_op.add_column(sa.Column("is_tor_exit_node_suspected", sa.Boolean(), nullable=True))

    # --- WHOIS provenance on domains ---
    with op.batch_alter_table("domains") as batch_op:
        batch_op.add_column(sa.Column("whois_source", sa.String(length=64), nullable=True))

    # --- DNS observations (append-only) ---
    op.create_table(
        "dns_observations",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("case_id", sa.Uuid(), sa.ForeignKey("cases.id", ondelete="CASCADE"), nullable=False),
        sa.Column("query_type", sa.String(length=16), nullable=False),
        sa.Column("query_name", sa.String(length=255), nullable=False),
        sa.Column("result", sa.Text(), nullable=True),
        sa.Column("success", sa.Boolean(), nullable=False),
        sa.Column("source", sa.String(length=64), nullable=False, server_default="dnspython"),
        sa.Column("ttl", sa.Integer(), nullable=True),
        sa.Column("error_detail", sa.Text(), nullable=True),
    )
    op.create_index("ix_dns_observations_case_id", "dns_observations", ["case_id"])

    # --- Blockchain (hash-chain) evidence-integrity ledger (append-only) ---
    op.create_table(
        "blockchain_anchors",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("case_id", sa.Uuid(), sa.ForeignKey("cases.id"), nullable=True),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("evidence_sha256", sa.String(length=64), nullable=True),
        sa.Column("report_sha256", sa.String(length=64), nullable=True),
        sa.Column("previous_hash", sa.String(length=64), nullable=True),
        sa.Column("computed_hash", sa.String(length=64), nullable=False, unique=True),
        sa.Column("hash_timestamp", sa.Float(), nullable=False),
    )
    op.create_index("ix_blockchain_anchors_organization_id", "blockchain_anchors", ["organization_id"])
    op.create_index("ix_blockchain_anchors_computed_hash", "blockchain_anchors", ["computed_hash"], unique=True)


def downgrade() -> None:
    op.drop_index("ix_blockchain_anchors_computed_hash", table_name="blockchain_anchors")
    op.drop_index("ix_blockchain_anchors_organization_id", table_name="blockchain_anchors")
    op.drop_table("blockchain_anchors")

    op.drop_index("ix_dns_observations_case_id", table_name="dns_observations")
    op.drop_table("dns_observations")

    with op.batch_alter_table("domains") as batch_op:
        batch_op.drop_column("whois_source")

    with op.batch_alter_table("ips") as batch_op:
        batch_op.drop_column("is_tor_exit_node_suspected")
        batch_op.drop_column("is_vpn_or_proxy_suspected")
        batch_op.drop_column("hosting_classification_source")
        batch_op.drop_column("hosting_classification")
        batch_op.drop_column("ptr_hostname")
        batch_op.drop_column("geolocation_source")

    with op.batch_alter_table("email_messages") as batch_op:
        batch_op.drop_column("origin_determined")
        batch_op.drop_column("origin_reasoning")
        batch_op.drop_column("origin_confidence")
        batch_op.drop_column("origin_ip")
