"""Per-device "normal silence": quiet devices (a switch that logs a few times a day, a small remote site) get their
own limit before they count as silent/offline, instead of the global rule value.

Revision ID: 0022
Revises: 0021
Create Date: 2026-10-07
"""
from alembic import op

revision = "0022"
down_revision = "0021"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE devices ADD COLUMN silent_after_minutes integer "
               "CHECK (silent_after_minutes IS NULL OR silent_after_minutes BETWEEN 5 AND 10080)")


def downgrade() -> None:
    op.execute("ALTER TABLE devices DROP COLUMN silent_after_minutes")
