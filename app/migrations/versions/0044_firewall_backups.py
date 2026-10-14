"""Local copies of the UniFi consoles' own backup files (.unf), stored encrypted on the backup disk.

Revision ID: 0044
Revises: 0043
Create Date: 2026-10-11
"""
from alembic import op

from app.config import get_settings

revision = "0044"
down_revision = "0043"
branch_labels = None
depends_on = None


def upgrade() -> None:
    s = get_settings()
    app, web = s.db_app_user, s.db_web_user
    op.execute("""
        CREATE TABLE firewall_backups (
            id          bigserial PRIMARY KEY,
            client_id   integer NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
            device_id   integer NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
            filename    text NOT NULL,
            taken_at    timestamptz,                   -- when the console made the backup
            version     text,                          -- UniFi Network version
            size        bigint NOT NULL,
            sha256      text NOT NULL,
            path        text NOT NULL,                 -- encrypted file under FW_BACKUP_DIR
            fetched_at  timestamptz NOT NULL DEFAULT now(),
            UNIQUE (device_id, filename)
        )
    """)
    op.execute(f'GRANT SELECT ON firewall_backups TO "{web}"')
    op.execute("ALTER TABLE firewall_backups ENABLE ROW LEVEL SECURITY")
    op.execute(f'CREATE POLICY app_all ON firewall_backups TO "{app}" USING (true) WITH CHECK (true)')
    op.execute(f'CREATE POLICY web_scope ON firewall_backups TO "{web}" USING (client_id = ANY ((SELECT app_client_ids())::integer[]))')


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS firewall_backups")
