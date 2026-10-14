"""Alert e-mail subject prefix editable in Admin -> Mail ("<prefix>: <what happened> at <client>"); empty = ALERT_SUBJECT_PREFIX.

Revision ID: 0036
Revises: 0035
Create Date: 2026-10-09
"""
from alembic import op

revision = "0036"
down_revision = "0035"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE mail_settings ADD COLUMN subject_prefix text NOT NULL DEFAULT ''")


def downgrade() -> None:
    op.execute("ALTER TABLE mail_settings DROP COLUMN subject_prefix")
