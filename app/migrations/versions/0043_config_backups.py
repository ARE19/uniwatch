"""Configuration backups of each UniFi console (networks, Wi-Fi, firewall, port forwards, routes, settings ...), secrets
redacted; a new version is stored only when a section changed, with the object-level changes against the previous one.

Revision ID: 0043
Revises: 0042
Create Date: 2026-10-11
"""
from alembic import op

from app.config import get_settings

revision = "0043"
down_revision = "0042"
branch_labels = None
depends_on = None


def upgrade() -> None:
    s = get_settings()
    app, web = s.db_app_user, s.db_web_user
    op.execute("""
        CREATE TABLE config_snapshots (
            id         bigserial PRIMARY KEY,
            host_id    text NOT NULL,
            client_id  integer NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
            device_id  integer REFERENCES devices(id) ON DELETE SET NULL,
            section    text NOT NULL,                  -- networkconf, wlanconf, firewall-policies, ...
            taken_at   timestamptz NOT NULL,
            hash       text NOT NULL,
            objects    integer NOT NULL,
            data       jsonb NOT NULL,                 -- normalized, secrets redacted
            changes    jsonb,                          -- against the previous version (NULL for the first backup)
            summary    text NOT NULL
        )
    """)
    op.execute("CREATE INDEX config_snapshots_host_section ON config_snapshots (host_id, section, taken_at DESC)")
    op.execute("CREATE INDEX config_snapshots_client ON config_snapshots (client_id, taken_at DESC)")
    op.execute(f'GRANT SELECT ON config_snapshots TO "{web}"')
    op.execute("ALTER TABLE config_snapshots ENABLE ROW LEVEL SECURITY")
    op.execute(f'CREATE POLICY app_all ON config_snapshots TO "{app}" USING (true) WITH CHECK (true)')
    op.execute(f'CREATE POLICY web_scope ON config_snapshots TO "{web}" USING (client_id = ANY ((SELECT app_client_ids())::integer[]))')


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS config_snapshots")
