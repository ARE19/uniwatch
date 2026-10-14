"""Allow vendor 'dns' (the DNS forwarder log source).

Revision ID: 0016
Revises: 0015
Create Date: 2026-10-07
"""
from alembic import op

revision = "0016"
down_revision = "0015"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Migration 0002's naming convention produced "ck_devices_ck_devices_vendor"; drop whichever exists.
    op.execute("ALTER TABLE devices DROP CONSTRAINT IF EXISTS ck_devices_ck_devices_vendor")
    op.execute("ALTER TABLE devices DROP CONSTRAINT IF EXISTS ck_devices_vendor")
    op.execute("ALTER TABLE devices ADD CONSTRAINT ck_devices_vendor_allowed CHECK (vendor IN ('unifi', 'fortinet', 'dns', 'other'))")


def downgrade() -> None:
    op.execute("ALTER TABLE devices DROP CONSTRAINT IF EXISTS ck_devices_vendor_allowed")
    op.execute("UPDATE devices SET vendor = 'other' WHERE vendor = 'dns'")
    op.execute("ALTER TABLE devices ADD CONSTRAINT ck_devices_ck_devices_vendor CHECK (vendor IN ('unifi', 'fortinet', 'other'))")
