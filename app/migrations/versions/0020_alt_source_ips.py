"""Additional syslog/NetFlow source IPs per device (dual-WAN firewalls send from whichever WAN is active).

Revision ID: 0020
Revises: 0019
Create Date: 2026-10-07
"""
from alembic import op

revision = "0020"
down_revision = "0019"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE devices ADD COLUMN alt_source_ips inet[] NOT NULL DEFAULT '{}'")


def downgrade() -> None:
    op.execute("ALTER TABLE devices DROP COLUMN alt_source_ips")
