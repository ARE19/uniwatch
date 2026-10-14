"""The UniFi Site Manager API key can be saved in the portal (System Settings -> UniFi Site Manager), stored encrypted;
a saved key replaces UNIFI_SITE_MANAGER_API_KEY from .env.

Revision ID: 0046
Revises: 0045
Create Date: 2026-10-14
"""
from alembic import op

from app.config import get_settings

revision = "0046"
down_revision = "0045"
branch_labels = None
depends_on = None


def upgrade() -> None:
    s = get_settings()
    op.execute("""
        CREATE TABLE sitemanager_settings (
            id           smallint PRIMARY KEY DEFAULT 1 CHECK (id = 1),
            api_key_enc  text NOT NULL,
            updated_at   timestamptz NOT NULL DEFAULT now(),
            updated_by   text
        )
    """)
    op.execute(f'GRANT SELECT, INSERT, UPDATE, DELETE ON sitemanager_settings TO "{s.db_web_user}"')
    op.execute("ALTER TABLE sitemanager_settings ENABLE ROW LEVEL SECURITY")
    op.execute(f'CREATE POLICY app_all ON sitemanager_settings TO "{s.db_app_user}" USING (true) WITH CHECK (true)')
    # Web: staff only in the database (the page itself is admin-only).
    op.execute(f'CREATE POLICY web_staff ON sitemanager_settings TO "{s.db_web_user}" USING ((SELECT app_is_staff())) '
               f'WITH CHECK ((SELECT app_is_staff()))')


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS sitemanager_settings")
