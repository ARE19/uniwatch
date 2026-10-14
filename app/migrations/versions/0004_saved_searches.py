"""Phase 4: saved searches for Log View.

Revision ID: 0004
Revises: 0003
Create Date: 2026-10-06
"""
import sqlalchemy as sa
from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "saved_searches",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("user_id", sa.Integer, sa.ForeignKey("users.id", ondelete="CASCADE", name="fk_saved_searches_user_id_users"), nullable=False),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("query", sa.Text, nullable=False),          # the Log View query string (filters only)
        sa.Column("shared", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_saved_searches_user_id", "saved_searches", ["user_id"])


def downgrade() -> None:
    op.drop_table("saved_searches")
